//! Constructs complete public ordinary models separately from the wire tables.
//!
//! Model equality checks every nested field. Request scope is inert constructor
//! data; no token, signature, policy or physical owner is authenticated.

use super::support::{Value, bytes, encode, map, properties, text};
use Value::{Array, Bool, UInt};
use terrane_format::auth::{Request, RequestRoot, Verb};
use terrane_format::gc::publication::evidence::*;
use terrane_format::gc::publication::{BackendBinding, RemoteProvider};
use terrane_format::refs::*;

/// Constructs the complete ordinary local/S3/GCS owner models.
pub(super) fn owner(provider: &str) -> PhysicalRegistration {
    if provider == "local" {
        return PhysicalRegistration::Local(LocalOriginalRegistration {
            original_id: [1; 32],
            root: b"/fixture/bucket".to_vec(),
            domain: "public".into(),
            root_device: 11,
            root_inode: 12,
            coordination_device: 13,
            coordination_inode: 14,
            control: b"/fixture/control".to_vec(),
        });
    }
    PhysicalRegistration::Remote(RemoteOriginalRegistration {
        original_id: [1; 32],
        domain: "public".into(),
        control: b"original/control".to_vec(),
        binding: BackendBinding::Remote {
            provider: if provider == "s3" {
                RemoteProvider::S3
            } else {
                RemoteProvider::Gcs
            },
            endpoint: "https://storage.invalid".into(),
            bucket: "fixture-bucket".into(),
            prefix: b"prefix/".to_vec(),
            resource_nonce: [2; 32],
            coordination_key: b"coordination/key".to_vec(),
            coordination_nonce: [3; 32],
        },
    })
}

/// Constructs complete registered pin alternatives, with exact typed kinds.
///
/// # Panics
/// Panics for fixture kinds outside the six registered cases.
pub(super) fn pin(kind: u8, provider: &str) -> RequiredControlPin {
    let (typed_kind, key) = match kind {
        0 => (ControlKind::Registration, "registration.cbor".into()),
        1 => (
            ControlKind::Bootstrap,
            format!("bootstrap-{}-{}-24.cbor", "01".repeat(32), "05".repeat(32)),
        ),
        2 => (
            ControlKind::Association,
            format!("commit-{}.cbor", "06".repeat(32)),
        ),
        3 => (
            ControlKind::Import,
            format!("import-{}.cbor", "07".repeat(32)),
        ),
        4 => (
            ControlKind::ImportBinding,
            format!("import-binding-{}.cbor", "08".repeat(32)),
        ),
        5 => (
            ControlKind::ImportTrust,
            format!("import-trust-{}.cbor", "09".repeat(32)),
        ),
        _ => panic!("registered kind"),
    };
    RequiredControlPin {
        kind: typed_kind,
        owner: owner(provider),
        key,
        digest: [20 + kind; 32],
    }
}

/// Constructs the complete canonical control set in independently fixed order.
pub(super) fn controls(full: bool) -> Vec<RequiredControlPin> {
    let mut pins = vec![];
    if full {
        for kind in 0..6 {
            // Five-element remote owner bytes precede nine-element local bytes;
            // the shorter S3 provider spelling precedes GCS in canonical owners.
            for provider in ["s3", "gcs", "local"] {
                pins.push(pin(kind, provider));
            }
        }
    }
    pins
}

/// Constructs independently transcribed full property and override layer bytes.
pub(super) fn layers() -> Vec<ConsumedRootLayer> {
    vec![
        ConsumedRootLayer {
            properties: encode(&properties(vec![
                (
                    "acl",
                    Array(vec![
                        Array(vec![text("alice"), UInt(31)]),
                        Array(vec![text("alice"), UInt(0)]),
                    ]),
                ),
                ("strict-attrs", Bool(true)),
                ("hashes", Array(vec![text("sha256"), text("sha512")])),
                ("domain", text("public")),
            ])),
            overrides: encode(&properties(vec![
                ("retain", text("forever")),
                ("store", text("fixture-store")),
            ])),
        },
        ConsumedRootLayer {
            properties: encode(&properties(vec![
                ("reassembly", text("always")),
                ("domain", text("group:readers")),
                ("prefetch", text("none")),
            ])),
            overrides: encode(&properties(vec![
                ("hashes", Array(vec![text("sha256")])),
                ("domain", text("private:leaf")),
            ])),
        },
    ]
}

/// Constructs a complete typed occurrence preserving every layer byte.
pub(super) fn root(path: &[u8], layers: Vec<ConsumedRootLayer>) -> ConsumedRootPolicy {
    ConsumedRootPolicy {
        root: [30; 32],
        path: path.to_vec(),
        layers,
    }
}

/// Constructs exact ordered/repeated typed root occurrences for a view.
pub(super) fn view(domain: &str, empty: bool) -> ConsumedViewPolicy {
    ConsumedViewPolicy {
        view: [31; 32],
        default_domain: domain.into(),
        roots: if empty {
            vec![]
        } else {
            vec![
                root(b"/z", layers()),
                root(b"/a", layers()),
                root(b"/z", layers()),
            ]
        },
    }
}

/// Constructs independently transcribed complete configured locality.
pub(super) fn locality() -> Locality {
    Locality {
        region: Some("region".into()),
        zone: Some("zone".into()),
        host: Some("host".into()),
    }
}

/// Constructs every represented configuration field and optional alternative.
pub(super) fn config(full: bool) -> TrustedGuardConfig {
    TrustedGuardConfig {
        store_name: "fixture-store".into(),
        private_domain_hint: "private:hint".into(),
        home: if full {
            locality()
        } else {
            Locality::default()
        },
        initial_acl: vec![
            AuthorityGrant {
                principal: "alice".into(),
                verbs: 31,
            },
            AuthorityGrant {
                principal: "alice".into(),
                verbs: 0,
            },
        ],
        minimum_chunk_size: 262144,
        storage_domain: "public".into(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: SeededChunkProfile {
            minimum: 262144,
            target: 1048576,
            maximum: 4194304,
            window: 48,
            normalization: 2,
            seed: [40; 32],
        },
        policy_authority: full.then(|| "policy:fixture".into()),
    }
}

/// Constructs the complete typed registered semantics and inert-name fence.
pub(super) fn registries(later: bool) -> ConfiguredRegistryInputs {
    let mut names = [
        "store",
        "chunk",
        "compression",
        "encryption",
        "retain",
        "domain",
        "dedup",
        "redundancy",
        "degraded",
        "durability",
        "replicate",
        "home",
        "warm",
        "quota",
        "compaction_threshold",
        "whole_pack_threshold",
        "gap_merge_bytes",
        "span_max_bytes",
        "trust",
        "baseline",
        "merge",
        "writers",
        "reflog_retain",
        "prefetch",
        "reassembly",
        "passthrough",
        "wipe",
        "on-release",
        "acl",
        "hashes",
        "classify",
        "index",
        "strict-attrs",
    ];
    names.sort_unstable();
    ConfiguredRegistryInputs {
        property_revision: 1,
        behavioral_properties: names.into_iter().map(String::from).collect(),
        attribute_revision: 1,
        selector_revision: 1,
        tree_revision: 1,
        chunk_revision: 1,
        identity_profile: "terrane-v1".into(),
        later_properties: if later {
            vec!["future-note".into()]
        } else {
            vec![]
        },
    }
}

/// Constructs all nested used inputs, preserving null and explicit empty lists.
pub(super) fn used(full: bool, later: bool) -> LineageUsedInputs {
    let issuers = if full {
        vec![
            IssuerRow {
                issuer: "issuer-a".into(),
                key_id: "key-a".into(),
                public_key: [41; 32],
                retired_at: None,
            },
            IssuerRow {
                issuer: "issuer-a".into(),
                key_id: "key-b".into(),
                public_key: [42; 32],
                retired_at: Some(100),
            },
        ]
    } else {
        vec![]
    };
    let disclosures = if full {
        vec![
            DisclosureRow {
                repository: "01".repeat(32),
                domain: "public".into(),
                public_key: [43; 32],
                not_before: 10,
                not_after: None,
            },
            DisclosureRow {
                repository: "01".repeat(32),
                domain: "tenant:fixture".into(),
                public_key: [44; 32],
                not_before: 20,
                not_after: Some(30),
            },
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
        views = vec![ConsumedViewPolicy {
            view: [31; 32],
            default_domain: "public".into(),
            roots: vec![root(
                b"/",
                vec![ConsumedRootLayer {
                    properties: encode(&properties(vec![("future-note", text("inert"))])),
                    overrides: vec![0xa0],
                }],
            )],
        }];
    }
    LineageUsedInputs {
        issuers,
        disclosures,
        controls: controls(full),
        registries: registries(later),
        configuration: config(full),
        views,
        view_interpretations: None,
    }
}

/// Constructs a complete signed Commit with ordinary constructor-only context.
///
/// # Panics
/// Panics if the independently specified ordinary context has invalid syntax.
pub(super) fn commit(full: bool) -> Commit {
    let token = Array(vec![map(vec![
        (12, bytes(&[47; 64])),
        (11, bytes(&[46; 32])),
        (9, Array(vec![Array(vec![text("refs/heads/*"), UInt(4)])])),
        (8, bytes(&[45; 16])),
        (6, UInt(200)),
        (5, Array(vec![text("readers")])),
        (4, UInt(2)),
        (3, text("alice")),
        (2, text("alice")),
        (1, text("issuer-a")),
    ])]);
    let locality = locality();
    let roots = [
        RequestRoot {
            path: b"/graft",
            domain: "private:leaf",
        },
        RequestRoot {
            path: b"/",
            domain: "public",
        },
    ];
    let request = Request {
        reference: b"refs/heads/_/authored",
        verb: Verb::Commit,
        roots: &roots,
        now: 100,
        surface: "sdk",
        locality: &locality,
        epochs: &[],
    };
    Commit {
        tree: [30; 32],
        parents: vec![[48; 32]],
        timestamp: 101,
        message: "inert lineage fields".into(),
        provenance: Provenance {
            issuer: "issuer-a".into(),
            token_id: [45; 16],
            subject: "alice".into(),
            kind: PrincipalKind::Workload,
            workload_identity: full.then(|| "workload:fixture".into()),
            process: "fixture:lineage".into(),
            observed_at: 100,
            writer_epoch: 24,
            source: CommitSource::Imported,
            embedded_token: full.then(|| encode(&token)),
        },
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe: None,
            conflicted: full.then_some(false),
            lease: full.then(|| Lease {
                owner: "lease:fixture".into(),
                expiry: 200,
            }),
            required_properties: full
                .then(|| encode(&properties(vec![("hashes", Array(vec![text("sha256")]))]))),
            entry_receipts: full.then(Vec::new),
            commit_context: full.then(|| {
                CommitContext::from_request(&request)
                    .unwrap_or_else(|error| panic!("context: {error}"))
            }),
        },
        packs: full.then(|| {
            vec![PackLocation {
                pack_id: [50; 16],
                locality,
            }]
        }),
        signature: Some([49; 64]),
    }
}

/// Constructs every optional selected source RefRecord field separately.
///
/// # Panics
/// Panics if the independently specified tag fixture has invalid syntax.
pub(super) fn source(commit_id: [u8; 32], full: bool) -> RefRecord {
    RefRecord {
        commit: commit_id,
        seq: 24,
        writer_epoch: 25,
        home: if full {
            locality()
        } else {
            Locality::default()
        },
        policy: full.then(|| RefPolicy {
            multi_writer: Some(true),
            merge_policies: Some(vec![
                MergePolicy::PreferOurs,
                MergePolicy::KeepConflict,
                MergePolicy::PreferOurs,
            ]),
            retention: Some(Retention::Ttl(300)),
            conflicted: Some(false),
            snapshot: Some(SnapshotEnvelope {
                tag: RefName::parse("refs/tags/_/selected")
                    .unwrap_or_else(|error| panic!("tag: {error}")),
                commit: commit_id,
                attestation: encode(&properties(vec![("note", text("opaque"))])),
                signer_key: "fixture:key".into(),
                signature: [51; 64],
            }),
        }),
        candidate_id: full.then_some([52; 32]),
    }
}

/// Constructs the complete checked-source ordinary model from separate inputs.
pub(super) fn checked(
    provider: &str,
    full: bool,
    maximum: bool,
    commit_bytes: Vec<u8>,
    commit_id: [u8; 32],
) -> CheckedLineage {
    CheckedLineage {
        source_name: if full {
            "refs/tags/_/selected"
        } else {
            "refs/heads/_/source"
        }
        .into(),
        source: source(commit_id, full),
        commit_id,
        commit_bytes,
        guard_digest: [53; 32],
        loss_generation: if maximum { u64::MAX } else { 24 },
        controls: controls(full),
        original: owner(provider),
        used: used(full, false),
    }
}
