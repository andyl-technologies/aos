//! Independent primitive models and genuinely verified core histories.
//!
//! These fixtures never construct native verified/admitted authority wrappers.
#![allow(
    clippy::unwrap_used,
    reason = "invalid independently supplied fixtures must panic"
)]

use alloc::{borrow::ToOwned, string::ToString, vec, vec::Vec};

use crate::auth::{self, Authority, Grant, IssuerKey, Request, Token, Verb, Verbs};
use crate::identity::Digest;
use crate::provenance::{VerifiedHistory, sign, verify};
use crate::refs::{Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance};

/// Uses the registered minimum chunk size.
pub(super) const MINIMUM: u64 = 262144;

/// Returns the actual token issuer verification key.
pub(super) fn issuer_keys() -> Vec<IssuerKey> {
    vec![IssuerKey {
        issuer: "issuer".to_string(),
        key_id: "issuer-key".to_string(),
        public_key: auth::public_key_from_secret(&[7; 32]),
        retirement: None,
    }]
}

fn unsigned_commit() -> Commit {
    let token = Token::issue(
        Authority {
            issuer: "issuer".to_string(),
            key_id: "issuer-key".to_string(),
            subject: "build/baseline".to_string(),
            kind: PrincipalKind::Workload,
            groups: vec!["baseline".to_string()],
            not_after: 200,
            not_before: Some(50),
            token_id: [3; 16],
            grants: vec![
                Grant::new("refs/heads/main".to_string(), Verbs::new(4).unwrap()).unwrap(),
            ],
            workload: Some("workload-identity".to_string()),
        },
        &[7; 32],
        auth::public_key_from_secret(&[9; 32]),
    )
    .unwrap();

    Commit {
        tree: [1; 32],
        parents: Vec::new(),
        provenance: Provenance {
            issuer: "issuer".to_string(),
            token_id: [3; 16],
            subject: "build/baseline".to_string(),
            kind: PrincipalKind::Workload,
            workload_identity: Some("workload-identity".to_string()),
            process: "test/sdk".to_string(),
            observed_at: 100,
            writer_epoch: 4,
            source: CommitSource::Built,
            embedded_token: Some(token.encode()),
        },
        timestamp: 100,
        message: "build".to_string(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "default".to_string(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: None,
        },
        packs: None,
        signature: None,
    }
}

/// Runs a fixture operation with its actual Commit capability request.
///
/// # Panics
/// Propagates any panic from the caller's action.
pub(super) fn with_request<T>(action: impl FnOnce(&Request<'_>) -> T) -> T {
    let locality = Locality::default();
    action(&Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: &[],
        now: 100,
        surface: "sdk",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    })
}

// Independent raw primitive inputs bypass the physical Node and context encoders.
/// Frozen original behavioral names, independently written from the registry.
const LEGACY: &[&str] = &[
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

/// Returns the independently enumerated revision vocabulary.
pub(super) fn vocabulary(revision: u64) -> Vec<&'static str> {
    let mut names = LEGACY.to_vec();
    if revision >= 2 {
        names.push("index-roots");
    }
    if revision >= 3 {
        names.push("index-gaps");
    }
    names.sort_unstable();
    names
}

/// Writes an unsigned primitive with a chosen major type.
fn head(major: u8, value: u64) -> Vec<u8> {
    let mut bytes = vec![major << 5];
    match value {
        0..=23 => bytes[0] |= value as u8,
        24..=255 => {
            bytes[0] |= 24;
            bytes.push(value as u8);
        }
        256..=65535 => {
            bytes[0] |= 25;
            bytes.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65536..=4294967295 => {
            bytes[0] |= 26;
            bytes.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            bytes[0] |= 27;
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    bytes
}

/// Encodes an independent unsigned integer.
pub(super) fn uint(value: u64) -> Vec<u8> {
    head(0, value)
}

/// Encodes an independent byte string.
pub(super) fn bytes(value: &[u8]) -> Vec<u8> {
    let mut result = head(2, value.len() as u64);
    result.extend_from_slice(value);
    result
}

/// Encodes an independent text string.
pub(super) fn text(value: &str) -> Vec<u8> {
    let mut result = head(3, value.len() as u64);
    result.extend_from_slice(value.as_bytes());
    result
}

/// Joins independently encoded array elements.
pub(super) fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut result = head(4, values.len() as u64);
    for value in values {
        result.extend_from_slice(value);
    }
    result
}

/// Sorts raw map keys by unsigned encoded bytes.
pub(super) fn map(mut rows: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let mut result = head(5, rows.len() as u64);
    for (key, value) in rows {
        result.extend(key);
        result.extend(value);
    }
    result
}

fn properties(rows: &[(&str, Vec<u8>)]) -> Vec<u8> {
    map(rows
        .iter()
        .map(|(name, value)| (text(name), value.clone()))
        .collect())
}

/// Constructs canonical leaf rows and raw root properties.
pub(super) fn node(entries: &[(&[u8], Vec<u8>)], props: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let rows = entries
        .iter()
        .map(|(path, entry)| array(&[bytes(path), uint(0), entry.clone()]))
        .collect::<Vec<_>>();
    map(vec![
        (uint(1), uint(0)),
        (uint(2), array(&rows)),
        (uint(3), properties(props)),
    ])
}

// Signing authenticates the capability, and verification checks the resulting
// signature again. No fixture sets a verified or admitted history flag.
/// Signs, verifies and inserts an actual core Commit with its receipt.
///
/// # Panics
/// Panics if the fixture does not satisfy production verification.
pub(super) fn retain_selected(
    history: &mut VerifiedHistory,
    root: Digest,
    message: &str,
    selected: crate::properties::selected::Selection,
) -> Digest {
    retain_view_with_leaf(history, root, root, b"file", message, selected)
}

fn retain_view_with_leaf(
    history: &mut VerifiedHistory,
    root: Digest,
    leaf_root: Digest,
    path: &[u8],
    message: &str,
    selected: crate::properties::selected::Selection,
) -> Digest {
    let mut unsigned = unsigned_commit();
    unsigned.tree = root;
    unsigned.message = message.to_owned();
    unsigned.profile_pair.entry_receipts = Some(vec![crate::refs::EntryReceipt {
        root: leaf_root,
        path: path.to_vec(),
        origin: crate::refs::EntryOrigin::Current,
        attributes: None,
        reintroduced_from: None,
        disclosure_proof: None,
    }]);
    let signed =
        with_request(|request| sign(unsigned, &[9; 32], &issuer_keys(), request, 4)).unwrap();
    let verified =
        with_request(|request| verify(signed.commit(), &issuer_keys(), request, 4)).unwrap();
    assert_eq!(signed.identity(), verified.identity());
    let view = verified.identity();
    history.insert_commit_selected(verified, selected).unwrap();
    view
}
