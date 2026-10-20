//! Constructs proof alternatives and their complete ordinary retirement records.
//!
//! Lease, nonce, elapsed-time, artifact and owner fields remain unauthenticated
//! data. Encoding/decoding these values neither performs retirement nor creates
//! a permission, verified proof, fence, backend, timer or authority holder.
//!
//! ```text
//! proof = [0] | [1, digest] | [2, fence, digest, removed, carried]
//!       | [3, authorization_bytes, carried] | [4, digest]
//! ```

use super::{
    publication,
    wire::{self, Value, a, b, bytes, m, s, u},
};
use terrane_format::{
    bucket::Tombstone,
    gc::{GcLease, publication::*, retirement::*},
};

/// Constructs primitive tombstone fields independently of the owning codec.
pub(super) fn tombstone_wire() -> Value {
    m(vec![
        (1, b(0x12, 16)),
        (2, u(3)),
        (3, u(4)),
        (4, u(0)),
        (5, u(2)),
    ])
}

fn witness() -> Vec<u8> {
    let mut wire = b"TRPK\x01\0\0\0".to_vec();
    wire.extend([0x12; 16]);
    wire.extend(b"TRIX");
    wire.extend([0; 8]);
    wire
}

fn index_digest() -> [u8; 32] {
    let mut raw = b"terrane-index-v1\0".to_vec();
    raw.extend(witness());
    *blake3::hash(&raw).as_bytes()
}

fn backend(local: bool) -> BackendBinding {
    if local {
        super::bindings::model("local")
    } else {
        BackendBinding::Remote {
            provider: RemoteProvider::S3,
            endpoint: "e".into(),
            bucket: "b".into(),
            prefix: vec![],
            resource_nonce: [1; 32],
            coordination_key: b"c".to_vec(),
            coordination_nonce: [2; 32],
        }
    }
}

fn backend_wire(local: bool) -> Value {
    if local {
        super::bindings::primitive("local")
    } else {
        a(vec![
            u(1),
            s("s3"),
            a(vec![s("e"), s("b"), bytes(vec![]), b(1, 32)]),
            a(vec![bytes(b"c"), b(2, 32)]),
        ])
    }
}

fn trash() -> RemoteArtifact {
    let tombstone = tombstone_wire();
    RemoteArtifact {
        key: format!("trash/3/{}", "12".repeat(16)),
        digest: wire::raw(&tombstone),
        size: tombstone.encode().len() as u64,
    }
}

fn trash_wire() -> Value {
    let tombstone = tombstone_wire();
    a(vec![
        s(format!("trash/3/{}", "12".repeat(16))),
        bytes(wire::raw(&tombstone)),
        u(tombstone.encode().len() as u64),
    ])
}

/// Constructs every field of the sweep/copied authorization ordinary data model.
pub(super) fn authorization(kind: &str, lineage: bool) -> PermanentDeleteAuthorization {
    let nonce = publication::NONCE;
    let exclusion = Exclusion {
        pack: [0x12; 16],
        cycle: 3,
        epoch: 2,
    };
    let lease = GcLease {
        holder: "A".into(),
        epoch: 2,
        expiry: 100,
    };
    let fence = RecordPointer {
        key: "gc/3/fence/2".into(),
        digest: [8; 32],
    };
    if kind == "sweep" {
        let base = format!("objects/pack/12/{}", "12".repeat(16));
        PermanentDeleteAuthorization::Sweep(RemoteSweepDeleteAuthorization {
            nonce,
            backend: backend(false),
            exclusion,
            lease,
            deletion_seconds: 2,
            artifacts: [
                RemoteArtifact {
                    key: format!("{base}.pack"),
                    digest: [7; 32],
                    size: 52,
                },
                RemoteArtifact {
                    key: format!("{base}.idx"),
                    digest: index_digest(),
                    size: 36,
                },
                trash(),
            ],
            witness: witness(),
            tombstone: tombstone_wire().encode(),
            deletion_elapsed_nanos: 2_000_000_000,
            fence,
            grace_seconds: 1,
            grace_elapsed_nanos: 1_000_000_000,
        })
    } else {
        let barrier = if kind == "local" {
            BarrierArtifact::Local(LocalBarrierArtifact {
                key: format!("trash/3/{}", "12".repeat(16)),
                nonce: [5; 32],
                tombstone: tombstone_wire().encode(),
                file_identity: vec![6],
            })
        } else {
            BarrierArtifact::Remote(trash())
        };
        PermanentDeleteAuthorization::Copied(CopiedRetirementAuthorization {
            nonce,
            backend: backend(kind == "local"),
            exclusion,
            lease,
            deletion_seconds: 2,
            barrier,
            tombstone: tombstone_wire().encode(),
            deletion_elapsed_nanos: 2_000_000_000,
            fence,
            grace_seconds: 1,
            grace_elapsed_nanos: 1_000_000_000,
            genesis: OwnershipSlot {
                revision: 0,
                digest: [9; 32],
            },
            preparation: OwnershipSlot {
                revision: 1,
                digest: [10; 32],
            },
            lineage_fence: lineage.then(|| RecordPointer {
                key: "gc/3/fence/2".into(),
                digest: [21; 32],
            }),
        })
    }
}

/// Constructs primitive authorization fields independently of any owning codec.
pub(super) fn authorization_wire(kind: &str, lineage: bool) -> Value {
    let mut fields = vec![
        (0, u(2)),
        (1, bytes(publication::NONCE)),
        (2, backend_wire(kind == "local")),
        (3, a(vec![b(0x12, 16), u(3), u(2)])),
        (4, m(vec![(1, s("A")), (2, u(2)), (3, u(100))])),
        (5, u(2)),
        (8, bytes(tombstone_wire().encode())),
        (9, u(2_000_000_000)),
        (10, a(vec![s("gc/3/fence/2"), b(8, 32)])),
        (11, u(1)),
        (12, u(1_000_000_000)),
        (13, u(1)),
    ];
    if kind == "sweep" {
        let base = format!("objects/pack/12/{}", "12".repeat(16));
        fields.push((
            6,
            a(vec![
                a(vec![s(format!("{base}.pack")), b(7, 32), u(52)]),
                a(vec![s(format!("{base}.idx")), bytes(index_digest()), u(36)]),
                trash_wire(),
            ]),
        ));
        fields.push((7, bytes(witness())));
    } else {
        let barrier = if kind == "local" {
            a(vec![
                s(format!("trash/3/{}", "12".repeat(16))),
                b(5, 32),
                a(vec![u(2), bytes(tombstone_wire().encode())]),
                bytes(vec![6]),
            ])
        } else {
            trash_wire()
        };
        fields.extend([
            (6, a(vec![Value::Null, Value::Null, barrier])),
            (14, u(1)),
            (15, a(vec![u(0), b(9, 32)])),
            (16, a(vec![u(1), b(10, 32)])),
        ]);
        if lineage {
            fields.push((17, a(vec![s("gc/3/fence/2"), b(21, 32)])));
        }
    }
    m(fields)
}

/// Constructs complete carried-source rows with opaque lineage digests.
pub(super) fn carried() -> Vec<SourceLineage> {
    vec![
        SourceLineage {
            name: publication::NAME.into(),
            digest: [23; 32],
        },
        SourceLineage {
            name: "refs/tags/_/alias".into(),
            digest: [24; 32],
        },
    ]
}

/// Constructs primitive carried-source rows separately from public rows.
pub(super) fn carried_wire() -> Value {
    a(vec![
        a(vec![s(publication::NAME), b(23, 32)]),
        a(vec![s("refs/tags/_/alias"), b(24, 32)]),
    ])
}

/// Constructs primitive collection proof fields with optional repeated witnesses.
pub(super) fn collection_wire(empty: bool, repeated: bool) -> Value {
    let mut removed = if empty {
        vec![]
    } else {
        vec![
            a(vec![b(0x12, 16), b(21, 32)]),
            a(vec![b(0x13, 16), b(22, 32)]),
        ]
    };
    if repeated {
        removed.push(a(vec![b(0x12, 16), b(21, 32)]));
    }
    a(vec![
        u(2),
        s("gc/3/fence/2"),
        b(20, 32),
        a(removed),
        if empty { a(vec![]) } else { carried_wire() },
    ])
}

/// Checks every proof case and each complete embedded authorization alternative.
///
/// # Panics
/// Panics if exact wires or complete independently constructed fields differ.
pub(super) fn check_models() {
    let tombstone = Tombstone {
        pack_id: [0x12; 16],
        cycle: 3,
        tombstoned_at: 4,
        removed_entries: 0,
        epoch: 2,
    };
    assert_eq!(
        Tombstone::decode(&tombstone_wire().encode())
            .unwrap_or_else(|error| panic!("nested tombstone decoding: {error}")),
        tombstone
    );
    assert_eq!(tombstone.encode(), tombstone_wire().encode());
    for (name, model, input) in [
        ("raw", PublicationProof::Raw, a(vec![u(0)])),
        (
            "candidate",
            PublicationProof::Candidate([18; 32]),
            a(vec![u(1), b(18, 32)]),
        ),
        (
            "guard",
            PublicationProof::Guard([19; 32]),
            a(vec![u(4), b(19, 32)]),
        ),
    ] {
        wire::check(
            &format!("control-proof-{name}"),
            model.clone(),
            input,
            model.encode(),
            PublicationProof::decode,
        );
    }
    for (label, empty, repeated) in [
        ("empty", true, false),
        ("full", false, false),
        ("repeated", false, true),
    ] {
        let mut removed = if empty {
            vec![]
        } else {
            vec![
                RemovedPack {
                    pack: [0x12; 16],
                    index: [21; 32],
                },
                RemovedPack {
                    pack: [0x13; 16],
                    index: [22; 32],
                },
            ]
        };
        if repeated {
            removed.push(RemovedPack {
                pack: [0x12; 16],
                index: [21; 32],
            });
        }
        let model = PublicationProof::Collection {
            fence_key: "gc/3/fence/2".into(),
            fence_digest: [20; 32],
            removed,
            carried: if empty { vec![] } else { carried() },
        };
        wire::check(
            &format!("control-proof-collection-{label}"),
            model.clone(),
            collection_wire(empty, repeated),
            model.encode(),
            PublicationProof::decode,
        );
    }
    for (kind, lineage) in [
        ("sweep", false),
        ("remote", false),
        ("remote", true),
        ("local", true),
    ] {
        let label = format!("{kind}{}", if lineage { "-lineage" } else { "" });
        let model = authorization(kind, lineage);
        let input = authorization_wire(kind, lineage);
        wire::check(
            &format!("control-authorization-{label}"),
            model.clone(),
            input.clone(),
            model.encode(),
            PermanentDeleteAuthorization::decode,
        );
        let carried = if lineage || kind == "sweep" {
            vec![SourceLineage {
                name: publication::NAME.into(),
                digest: [23; 32],
            }]
        } else {
            vec![]
        };
        let carried_wire = if carried.is_empty() {
            a(vec![])
        } else {
            a(vec![a(vec![s(publication::NAME), b(23, 32)])])
        };
        let model = PublicationProof::PermanentRetirement {
            authorization: input.encode(),
            carried,
        };
        wire::check(
            &format!("control-proof-retirement-{label}"),
            model.clone(),
            a(vec![u(3), bytes(input.encode()), carried_wire]),
            model.encode(),
            PublicationProof::decode,
        );
    }
}
