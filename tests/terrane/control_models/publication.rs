//! Constructs complete retained history, portable inventories and genesis rows.
//!
//! CAPABILITIES payload bytes are opaque presence witnesses, including empty
//! bytes. The pure publication codecs do not validate that payload or grant
//! registration, inventory, activation or selected-chain authority.
//!
//! ```text
//! snapshot = {0: 1, 1: revision, 2: origin, 3: projection, 4: prior_or_null}
//! transaction = {0: 1, 1: nonce, 2: old_or_null, 3: new_bytes,
//!                4: changes, 5: proof, 6: prior_slot_or_null, 7: snapshot}
//! ```

use super::{
    bindings,
    wire::{self, Value, a, b, bytes, m, s, u},
};
use terrane_format::{
    gc::publication::*,
    refs::{Locality, RefRecord},
};

/// Names the exact canonical branch used by the independent field models.
pub(super) const NAME: &str = "refs/heads/_/main";
/// Holds opaque operation nonce bytes without randomness or private authority.
pub(super) const NONCE: [u8; 32] = [0x34; 32];

/// Constructs the complete typed retained head independently of its wire.
pub(super) fn head() -> RefRecord {
    RefRecord {
        commit: [2; 32],
        seq: 1,
        writer_epoch: 3,
        home: Locality {
            region: Some("region".into()),
            zone: Some(String::new()),
            host: Some("host".into()),
        },
        policy: None,
        candidate_id: Some([10; 32]),
    }
}

/// Constructs complete primitive head fields, including absent policy.
pub(super) fn head_wire() -> Value {
    m(vec![
        (1, b(2, 32)),
        (2, u(1)),
        (3, u(3)),
        (4, m(vec![(1, s("region")), (2, s("")), (3, s("host"))])),
        (6, b(10, 32)),
    ])
}

/// Constructs sorted history rows containing all committed-selection cases.
pub(super) fn branches() -> Vec<HistoryEntry> {
    vec![
        HistoryEntry {
            name: "refs/conflicts/_/old/00000000000000000001".into(),
            selection: CommittedSelection::Unknown,
        },
        HistoryEntry {
            name: NAME.into(),
            selection: CommittedSelection::Selected(Box::new(head())),
        },
        HistoryEntry {
            name: "refs/jobs/_/never".into(),
            selection: CommittedSelection::Never,
        },
    ]
}

/// Constructs primitive sorted rows with the complete nested retained head.
pub(super) fn branches_wire() -> Value {
    a(vec![
        a(vec![
            s("refs/conflicts/_/old/00000000000000000001"),
            a(vec![u(2)]),
        ]),
        a(vec![s(NAME), a(vec![u(1), head_wire()])]),
        a(vec![s("refs/jobs/_/never"), a(vec![u(0)])]),
    ])
}

/// Constructs complete typed history with an unauthenticated origin stamp.
pub(super) fn history(kind: &str) -> SelectedHistory {
    SelectedHistory {
        branches: branches(),
        origin: bindings::model(kind),
    }
}

/// Constructs primitive history fields without using a history encoder.
pub(super) fn history_wire(kind: &str) -> Value {
    m(vec![
        (0, u(1)),
        (1, branches_wire()),
        (2, bindings::primitive(kind)),
    ])
}

/// Constructs full typed projection rows using independently encoded nested bytes.
pub(super) fn inventory(kind: &str) -> Vec<ProjectionEntry> {
    vec![
        ProjectionEntry {
            key: "CAPABILITIES".into(),
            value: Some(vec![]),
        },
        ProjectionEntry {
            key: "gc/lease".into(),
            value: None,
        },
        ProjectionEntry {
            key: "publication/SELECTED-HISTORY".into(),
            value: Some(history_wire(kind).encode()),
        },
        ProjectionEntry {
            key: "refs/conflicts/_/old/00000000000000000001:record".into(),
            value: None,
        },
        ProjectionEntry {
            key: format!("{NAME}:record"),
            value: Some(head_wire().encode()),
        },
        ProjectionEntry {
            key: "refs/jobs/_/never:record".into(),
            value: None,
        },
    ]
}

/// Constructs full primitive inventory independently of the public row models.
pub(super) fn inventory_wire(kind: &str) -> Value {
    a(vec![
        a(vec![s("CAPABILITIES"), bytes(vec![])]),
        a(vec![s("gc/lease"), Value::Null]),
        a(vec![
            s("publication/SELECTED-HISTORY"),
            bytes(history_wire(kind).encode()),
        ]),
        a(vec![
            s("refs/conflicts/_/old/00000000000000000001:record"),
            Value::Null,
        ]),
        a(vec![
            s(format!("{NAME}:record")),
            bytes(head_wire().encode()),
        ]),
        a(vec![s("refs/jobs/_/never:record"), Value::Null]),
    ])
}

/// Constructs a canonical relative snapshot key without accessing storage.
pub(super) fn snapshot_key(revision: u64) -> String {
    format!("publication/snapshots/{revision}:{}", "34".repeat(32))
}

/// Constructs complete public full/delta fields with independent nested bytes.
pub(super) fn snapshot(kind: &str, delta: usize) -> PortableSnapshot {
    let (revision, projection, predecessor) = if delta == 0 {
        (0, inventory(kind), None)
    } else {
        let projection = if delta == 1 {
            vec![]
        } else {
            vec![
                ProjectionEntry {
                    key: "CAPABILITIES".into(),
                    value: Some(vec![]),
                },
                ProjectionEntry {
                    key: "gc/lease".into(),
                    value: None,
                },
            ]
        };
        (
            1,
            projection,
            Some(PortableCurrent {
                key: snapshot_key(0),
                digest: [11; 32],
            }),
        )
    };
    PortableSnapshot {
        revision,
        origin: bindings::model(kind),
        projection,
        predecessor,
    }
}

/// Constructs primitive full/delta snapshot fields independently.
pub(super) fn snapshot_wire(kind: &str, delta: usize) -> Value {
    let rows = match delta {
        0 => inventory_wire(kind),
        1 => a(vec![]),
        _ => a(vec![
            a(vec![s("CAPABILITIES"), bytes(vec![])]),
            a(vec![s("gc/lease"), Value::Null]),
        ]),
    };
    m(vec![
        (0, u(1)),
        (1, u(u64::from(delta != 0))),
        (2, bindings::primitive(kind)),
        (3, rows),
        (
            4,
            if delta == 0 {
                Value::Null
            } else {
                a(vec![s(snapshot_key(0)), b(11, 32)])
            },
        ),
    ])
}

/// Constructs all populated publication-state fields and owner presence cases.
pub(super) fn state(kind: &str, owners: usize) -> PublicationState {
    PublicationState {
        revision: 0,
        loss_generation: 0,
        sources: vec![SourceLineage {
            name: NAME.into(),
            digest: [12; 32],
        }],
        binding: bindings::model(kind),
        branches: branches(),
        guard: Some([13; 32]),
        burn_owners: match owners {
            0 => None,
            1 => Some(vec![]),
            _ => Some(vec![PermanentBurnOwner {
                pack: [0x12; 16],
                selection: PermanentOwnerSelection::CopiedVisibility,
            }]),
        },
    }
}

/// Constructs primitive state fields with omitted versus present-empty owners.
pub(super) fn state_wire(kind: &str, owners: usize) -> Value {
    let mut fields = vec![
        (0, u(1)),
        (1, u(0)),
        (2, u(0)),
        (3, a(vec![a(vec![s(NAME), b(12, 32)])])),
        (4, bindings::primitive(kind)),
        (5, branches_wire()),
        (6, b(13, 32)),
    ];
    if owners != 0 {
        fields.push((
            7,
            if owners == 1 {
                a(vec![])
            } else {
                a(vec![a(vec![b(0x12, 16), a(vec![u(0)])])])
            },
        ));
    }
    m(fields)
}

/// Constructs all mandatory genesis changes and exact raw snapshot relationship.
pub(super) fn genesis(kind: &str) -> PublicationTransaction {
    let changes = inventory(kind)
        .into_iter()
        .map(|entry| LogicalChange {
            key: entry.key,
            expected: None,
            new: entry.value,
        })
        .collect();
    PublicationTransaction {
        nonce: NONCE,
        old: None,
        new: state(kind, 0),
        changes,
        proof: PublicationProof::Raw,
        predecessor: None,
        snapshot: PortableCurrent {
            key: snapshot_key(0),
            digest: wire::raw(&snapshot_wire(kind, 0)),
        },
    }
}

/// Constructs complete primitive genesis fields without an owning encoder.
pub(super) fn genesis_wire(kind: &str) -> Value {
    let rows = inventory_wire(kind)
        .array_mut()
        .iter()
        .map(|row| {
            let mut row = row.clone();
            let fields = row.array_mut();
            a(vec![fields[0].clone(), Value::Null, fields[1].clone()])
        })
        .collect();
    m(vec![
        (0, u(1)),
        (1, bytes(NONCE)),
        (2, Value::Null),
        (3, bytes(state_wire(kind, 0).encode())),
        (4, a(rows)),
        (5, a(vec![u(0)])),
        (6, Value::Null),
        (
            7,
            a(vec![
                s(snapshot_key(0)),
                bytes(wire::raw(&snapshot_wire(kind, 0))),
            ]),
        ),
    ])
}

/// Checks complete inventory, every nested field and exact genesis digest slots.
///
/// # Panics
/// Panics for any primitive/reference/owning mismatch or rejected positive.
pub(super) fn check_models() {
    assert_eq!(
        RefRecord::decode(&head_wire().encode())
            .unwrap_or_else(|error| panic!("nested head decoding: {error}")),
        head()
    );
    assert_eq!(
        head()
            .encode()
            .unwrap_or_else(|error| panic!("nested head encoding: {error}")),
        head_wire().encode()
    );
    for kind in ["local", "s3", "gcs"] {
        let model = history(kind);
        wire::check(
            &format!("control-history-{kind}"),
            model.clone(),
            history_wire(kind),
            model.encode(),
            SelectedHistory::decode,
        );
        for (delta, label) in [(0, "full"), (1, "delta-empty"), (2, "delta-rows")] {
            let model = snapshot(kind, delta);
            wire::check(
                &format!("control-snapshot-{kind}-{label}"),
                model.clone(),
                snapshot_wire(kind, delta),
                model.encode(),
                PortableSnapshot::decode,
            );
        }
        let model = genesis(kind);
        wire::check(
            &format!("control-genesis-{kind}"),
            model.clone(),
            genesis_wire(kind),
            model.encode(),
            PublicationTransaction::decode,
        );
        let snapshot_digest = wire::raw(&snapshot_wire(kind, 0));
        let model = PortableCurrent {
            key: snapshot_key(0),
            digest: snapshot_digest,
        };
        wire::check(
            &format!("control-portable-current-{kind}"),
            model.clone(),
            m(vec![
                (0, u(1)),
                (1, s(snapshot_key(0))),
                (2, bytes(snapshot_digest)),
            ]),
            model.encode(),
            PortableCurrent::decode,
        );
        let digest = wire::raw(&genesis_wire(kind));
        let model = PublicationCommit {
            revision: 0,
            predecessor: None,
            transaction_key: format!("publication/transactions/{}", "34".repeat(32)),
            transaction_digest: digest,
        };
        wire::check(
            &format!("control-commit-{kind}"),
            model.clone(),
            m(vec![
                (0, u(1)),
                (1, u(0)),
                (2, Value::Null),
                (3, s(&model.transaction_key)),
                (4, bytes(digest)),
            ]),
            model.encode(),
            PublicationCommit::decode,
        );
    }
    for index in 0..3 {
        let model = branches()[index].selection.clone();
        let mut row = branches_wire().array_mut()[index].clone();
        let input = row.array_mut()[1].clone();
        wire::check(
            &format!("control-selection-{index}"),
            model.clone(),
            input,
            model.encode(),
            CommittedSelection::decode,
        );
        let model = state("local", index);
        wire::check(
            &format!("control-state-owners-{index}"),
            model.clone(),
            state_wire("local", index),
            model.encode(),
            PublicationState::decode,
        );
    }
    let model = PublicationCurrent {
        revision: 0,
        digest: [16; 32],
    };
    wire::check(
        "control-publication-current",
        model.clone(),
        m(vec![(0, u(1)), (1, u(0)), (2, b(16, 32))]),
        model.encode(),
        PublicationCurrent::decode,
    );
    let model = PublicationCommit {
        revision: 1,
        predecessor: Some([16; 32]),
        transaction_key: format!("publication/transactions/{}", "34".repeat(32)),
        transaction_digest: [17; 32],
    };
    wire::check(
        "control-commit-next",
        model.clone(),
        m(vec![
            (0, u(1)),
            (1, u(1)),
            (2, b(16, 32)),
            (3, s(&model.transaction_key)),
            (4, b(17, 32)),
        ]),
        model.encode(),
        PublicationCommit::decode,
    );
}
