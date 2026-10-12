//! Transcribes complete lineage field tables independently of owning codecs.
//!
//! ```text
//! checked = {0: 1, 1: source_name, 2: source_bytes, 3: commit_id,
//!            4: commit_bytes, 5: guard_digest, 6: loss, 7: controls,
//!            8: original_registration, 9: used_inputs}
//! ```

use super::support::{Value, bytes, digest, encode, map, properties, text};
use Value::{Array, Bool, Null, UInt};

/// Names the complete registered behavioral set in unsigned text order.
pub(super) const BEHAVIOR: &[&str] = &[
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

/// Constructs every local or remote original-registration primitive field.
pub(super) fn owner(provider: &str) -> Value {
    if provider == "local" {
        return Array(vec![
            UInt(1),
            digest(1),
            bytes(b"/fixture/bucket"),
            text("public"),
            UInt(11),
            UInt(12),
            UInt(13),
            UInt(14),
            bytes(b"/fixture/control"),
        ]);
    }
    Array(vec![
        UInt(2),
        digest(1),
        text("public"),
        Array(vec![
            UInt(1),
            text(provider),
            Array(vec![
                text("https://storage.invalid"),
                text("fixture-bucket"),
                bytes(b"prefix/"),
                digest(2),
            ]),
            Array(vec![bytes(b"coordination/key"), digest(3)]),
        ]),
        bytes(b"original/control"),
    ])
}

/// Constructs all pin fields and their exact registered key spelling.
///
/// # Panics
/// Panics if the fixture's kind is outside the six registered alternatives.
pub(super) fn pin(kind: u8, provider: &str) -> Value {
    let key = match kind {
        0 => "registration.cbor".into(),
        1 => format!("bootstrap-{}-{}-24.cbor", "01".repeat(32), "05".repeat(32)),
        2 => format!("commit-{}.cbor", "06".repeat(32)),
        3 => format!("import-{}.cbor", "07".repeat(32)),
        4 => format!("import-binding-{}.cbor", "08".repeat(32)),
        5 => format!("import-trust-{}.cbor", "09".repeat(32)),
        _ => panic!("registered kind"),
    };
    Array(vec![
        UInt(u64::from(kind)),
        owner(provider),
        text(&key),
        digest(20 + kind),
    ])
}

/// Constructs complete canonical property and override bytes for two layers.
pub(super) fn layers() -> Vec<Value> {
    vec![
        Array(vec![
            bytes(&encode(&properties(vec![
                ("domain", text("public")),
                (
                    "acl",
                    Array(vec![
                        Array(vec![text("alice"), UInt(31)]),
                        Array(vec![text("alice"), UInt(0)]),
                    ]),
                ),
                ("hashes", Array(vec![text("sha256"), text("sha512")])),
                ("strict-attrs", Bool(true)),
            ]))),
            bytes(&encode(&properties(vec![
                ("store", text("fixture-store")),
                ("retain", text("forever")),
            ]))),
        ]),
        Array(vec![
            bytes(&encode(&properties(vec![
                ("domain", text("group:readers")),
                ("prefetch", text("none")),
                ("reassembly", text("always")),
            ]))),
            bytes(&encode(&properties(vec![
                ("domain", text("private:leaf")),
                ("hashes", Array(vec![text("sha256")])),
            ]))),
        ]),
    ]
}

/// Constructs a complete absolute root-policy occurrence.
pub(super) fn root(path: &[u8], layers: Vec<Value>) -> Value {
    Array(vec![digest(30), bytes(path), Array(layers)])
}

/// Constructs exact ordered/repeated root occurrences and a default domain.
pub(super) fn view(domain: &str, empty: bool) -> Value {
    let roots = if empty {
        vec![]
    } else {
        vec![
            root(b"/z", layers()),
            root(b"/a", layers()),
            root(b"/z", layers()),
        ]
    };
    Array(vec![digest(31), text(domain), Array(roots)])
}

/// Constructs all trusted-config slots as untrusted primitive data.
pub(super) fn config(full: bool) -> Value {
    map(vec![
        (0, UInt(1)),
        (1, text("fixture-store")),
        (2, text("private:hint")),
        (3, if full { locality() } else { map(vec![]) }),
        (
            4,
            Array(vec![
                Array(vec![text("alice"), UInt(31)]),
                Array(vec![text("alice"), UInt(0)]),
            ]),
        ),
        (5, UInt(262144)),
        (6, text("public")),
        (7, text("cdc-1m")),
        (
            8,
            Array(vec![
                UInt(262144),
                UInt(1048576),
                UInt(4194304),
                UInt(48),
                UInt(2),
                digest(40),
            ]),
        ),
        (9, if full { text("policy:fixture") } else { Null }),
    ])
}

/// Constructs the complete semantic-revision and property-name fences.
pub(super) fn registries(later: bool) -> Value {
    map(vec![
        (0, UInt(1)),
        (1, UInt(1)),
        (2, Array(BEHAVIOR.iter().map(|name| text(name)).collect())),
        (3, UInt(1)),
        (4, UInt(1)),
        (5, UInt(1)),
        (6, UInt(1)),
        (7, text("terrane-v1")),
        (
            8,
            Array(if later {
                vec![text("future-note")]
            } else {
                vec![]
            }),
        ),
    ])
}

/// Constructs complete used inputs including null/absence/inert-name alternatives.
pub(super) fn used(full: bool, later: bool) -> Value {
    let issuers = if full {
        vec![
            Array(vec![text("issuer-a"), text("key-a"), digest(41), Null]),
            Array(vec![text("issuer-a"), text("key-b"), digest(42), UInt(100)]),
        ]
    } else {
        vec![]
    };
    let disclosures = if full {
        vec![
            Array(vec![
                text(&"01".repeat(32)),
                text("public"),
                digest(43),
                UInt(10),
                Null,
            ]),
            Array(vec![
                text(&"01".repeat(32)),
                text("tenant:fixture"),
                digest(44),
                UInt(20),
                UInt(30),
            ]),
        ]
    } else {
        vec![]
    };
    let mut views = if full {
        vec![view("public", false), view("tenant:fixture", true)]
    } else {
        vec![]
    };
    if later {
        views = vec![Array(vec![
            digest(31),
            text("public"),
            Array(vec![root(
                b"/",
                vec![Array(vec![
                    bytes(&encode(&properties(vec![("future-note", text("inert"))]))),
                    bytes(&[0xa0]),
                ])],
            )]),
        ])];
    }
    map(vec![
        (0, UInt(1)),
        (1, Array(issuers)),
        (2, Array(disclosures)),
        (3, Array(controls(full))),
        (4, registries(later)),
        (5, config(full)),
        (6, Array(views)),
    ])
}

/// Constructs the canonical pin order by independently encoded owner bytes.
pub(super) fn controls(full: bool) -> Vec<Value> {
    let mut controls = vec![];
    if full {
        for kind in 0..6 {
            let mut owners: Vec<_> = ["local", "s3", "gcs"]
                .into_iter()
                .map(|provider| (encode(&owner(provider)), pin(kind, provider)))
                .collect();
            owners.sort_by(|left, right| left.0.cmp(&right.0));
            controls.extend(owners.into_iter().map(|(_, pin)| pin));
        }
    }
    controls
}

/// Constructs all three optional locality labels as primitive fields.
pub(super) fn locality() -> Value {
    map(vec![
        (1, text("region")),
        (2, text("zone")),
        (3, text("host")),
    ])
}

/// Constructs a canonical public token chain with opaque key/signature bytes.
pub(super) fn token() -> Value {
    Array(vec![map(vec![
        (1, text("issuer-a")),
        (2, text("alice")),
        (3, text("alice")),
        (4, UInt(2)),
        (5, Array(vec![text("readers")])),
        (6, UInt(200)),
        (8, bytes(&[45; 16])),
        (9, Array(vec![Array(vec![text("refs/heads/*"), UInt(4)])])),
        (11, digest(46)),
        (12, bytes(&[47; 64])),
    ])])
}

/// Constructs actual complete canonical signed Commit primitive fields.
pub(super) fn commit(full: bool) -> Value {
    let mut provenance = vec![
        (1, text("issuer-a")),
        (2, bytes(&[45; 16])),
        (3, text("alice")),
        (4, UInt(2)),
        (6, text("fixture:lineage")),
        (7, UInt(100)),
        (8, UInt(24)),
        (9, UInt(3)),
    ];
    let mut profile = vec![(1, UInt(1)), (2, text("cdc-1m"))];
    if full {
        provenance.extend([(5, text("workload:fixture")), (10, token())]);
        profile.extend([
            (4, Bool(false)),
            (5, map(vec![(1, text("lease:fixture")), (2, UInt(200))])),
            (6, properties(vec![("hashes", Array(vec![text("sha256")]))])),
            (7, Array(vec![])),
            (
                8,
                map(vec![
                    (1, text("refs/heads/_/authored")),
                    (2, text("sdk")),
                    (3, locality()),
                    (
                        4,
                        Array(vec![
                            Array(vec![bytes(b"/"), text("public")]),
                            Array(vec![bytes(b"/graft"), text("private:leaf")]),
                        ]),
                    ),
                ]),
            ),
        ]);
    }
    let mut fields = vec![
        (1, digest(30)),
        (2, Array(vec![digest(48)])),
        (3, map(provenance)),
        (4, UInt(101)),
        (5, text("inert lineage fields")),
        (6, map(profile)),
        (8, bytes(&[49; 64])),
    ];
    if full {
        fields.push((7, Array(vec![Array(vec![bytes(&[50; 16]), locality()])])));
    }
    map(fields)
}

/// Constructs a complete selected RefRecord, preserving policy and candidate slots.
pub(super) fn source(commit_id: &[u8; 32], full: bool) -> Value {
    let mut fields = vec![
        (1, bytes(commit_id)),
        (2, UInt(24)),
        (3, UInt(25)),
        (4, if full { locality() } else { map(vec![]) }),
    ];
    if full {
        fields.extend([
            (
                5,
                map(vec![
                    (1, Bool(true)),
                    (
                        2,
                        Array(vec![
                            text("prefer-ours"),
                            text("keep-conflict"),
                            text("prefer-ours"),
                        ]),
                    ),
                    (3, Array(vec![text("ttl"), UInt(300)])),
                    (4, Bool(false)),
                    (
                        5,
                        map(vec![
                            (1, text("refs/tags/_/selected")),
                            (2, bytes(commit_id)),
                            (3, properties(vec![("note", text("opaque"))])),
                            (4, text("fixture:key")),
                            (5, bytes(&[51; 64])),
                        ]),
                    ),
                ]),
            ),
            (6, digest(52)),
        ]);
    }
    map(fields)
}

/// Constructs all ten CheckedLineage slots and primitive Commit digest equality.
pub(super) fn checked(provider: &str, full: bool, maximum: bool) -> Value {
    let commit_bytes = encode(&commit(full));
    let commit_id = commit_id(&commit_bytes);
    map(vec![
        (0, UInt(1)),
        (
            1,
            text(if full {
                "refs/tags/_/selected"
            } else {
                "refs/heads/_/source"
            }),
        ),
        (2, bytes(&encode(&source(&commit_id, full)))),
        (3, bytes(&commit_id)),
        (4, bytes(&commit_bytes)),
        (5, digest(53)),
        (6, UInt(if maximum { u64::MAX } else { 24 })),
        (7, Array(controls(full))),
        (8, owner(provider)),
        (9, used(full, false)),
    ])
}

/// Computes only the registered domain-separated digest of exact Commit bytes.
pub(super) fn commit_id(wire: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"terrane-commit-v1\0");
    hash.update(wire);
    *hash.finalize().as_bytes()
}
