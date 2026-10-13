//! Builds ordinary canonical trees and genuinely signed, reverified history fixtures.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use super::*;

/// Uses the fixed registered cdc-1m minimum for every physical witness.
pub(super) const MINIMUM: u64 = 262144;

/// Copies independently supplied ordinary interpretation input for a checked record.
///
/// # Panics
/// Panics if the literal fixture revision or preservation names are invalid.
pub(super) fn association(
    verified: &VerifiedCommit,
    revision: u64,
    later: &[&str],
) -> RecordedAssociation {
    RecordedAssociation::new(
        verified.identity(),
        verified.commit().tree,
        RecordedContext::new(revision, 3, later).unwrap(),
    )
}

/// Inserts complete physical witnesses; property semantics are selected separately.
///
/// # Panics
/// Panics if the independently initialized physical tree is not canonical.
pub(super) fn store_tree(
    history: &mut VerifiedHistory,
    entries: Vec<LeafItem<'_>>,
    properties: Vec<Property<'_>>,
) -> Digest {
    let (root, bytes) = tree(entries, Some(properties));
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    root
}

/// Supplies fixed raw public-domain and deliberately future structural metadata.
pub(super) fn properties(revision: u64) -> Vec<Property<'static>> {
    let mut props = vec![Property {
        name: "domain",
        value: b"\x66public",
    }];
    if revision <= 2 {
        props.push(Property {
            name: "index-gaps",
            value: &[0],
        });
    }
    if revision == 1 {
        props.push(Property {
            name: "index-roots",
            value: &[0],
        });
    }
    props
}

/// Supplies independent preservation registrations, never decoded from tree bytes.
pub(super) fn later(revision: u64) -> &'static [&'static str] {
    match revision {
        1 => &["index-gaps", "index-roots"],
        2 => &["index-gaps"],
        _ => &[],
    }
}

/// Signs through real Token machinery and independently verifies the resulting record.
///
/// # Panics
/// Panics if the literal token, signature, scope or history insertion is invalid.
#[allow(
    clippy::too_many_arguments,
    reason = "Signed fixtures keep independently supplied authority and interpretation inputs explicit."
)]
pub(super) fn retained(
    history: &mut VerifiedHistory,
    root: Digest,
    parents: Vec<Digest>,
    message: &str,
    claims: &[RequestRoot<'_>],
    grants: Vec<Grant>,
    receipts: Vec<crate::refs::EntryReceipt>,
    context: &RecordedContext,
) -> VerifiedCommit {
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.parents = parents;
    commit.message = message.to_string();
    if !receipts.is_empty() {
        commit.profile_pair.entry_receipts = Some(receipts);
    }
    let signed = signed_grants(commit, claims, grants, vec![]);
    let verified = verify_history(
        signed.commit(),
        &issuer_keys(),
        claims,
        &[("refs/heads/main", 4)],
    )
    .unwrap();
    assert_eq!(signed.identity(), verified.identity());
    history
        .insert_commit_selected(
            verified.clone(),
            crate::properties::selected::Selection::Recorded(context.clone()),
        )
        .unwrap();
    verified
}

/// Supplies an independent original Commit grant, optionally including real Admin.
///
/// # Panics
/// Panics if the fixed reference or verb mask ceases to be valid.
pub(super) fn grants(admin: bool) -> Vec<Grant> {
    vec![
        Grant::new(
            "refs/heads/main".to_string(),
            Verbs::new(if admin { 20 } else { 4 }).unwrap(),
        )
        .unwrap(),
    ]
}

/// Authenticates the selected calculation with independently supplied original bootstrap.
///
/// # Errors
/// Returns actual verifier rejection for property, canonical scope or original authority failure.
pub(super) fn check(
    history: &mut VerifiedHistory,
    record: &VerifiedCommit,
    selected: &RecordedAssociation,
) -> Result<VerifiedRootScope, Rejected> {
    VerifiedRootScope::verify_with_recorded_properties_and_bootstrap(
        history,
        record.identity(),
        defaults(),
        Some(selected),
        fixture_bootstrap().authority,
        fixture_bootstrap(),
    )
}

/// Retains one genuinely checked modern public view with no structural properties.
///
/// # Panics
/// Panics if the literal canonical tree or signed view cannot be checked.
pub(super) fn modern() -> (VerifiedHistory, VerifiedCommit) {
    let mut history = VerifiedHistory::new(MINIMUM);
    let root = store_tree(
        &mut history,
        vec![item(b"file", entry(b"content"))],
        properties(3),
    );
    let record = retained(
        &mut history,
        root,
        vec![],
        "same modern view",
        &[RequestRoot {
            path: b"/",
            domain: PUBLIC,
        }],
        grants(false),
        vec![receipt(root, crate::refs::EntryOrigin::Current)],
        &RecordedContext::new(1, 3, later(1)).unwrap(),
    );
    (history, record)
}

/// Encodes one primitive CBOR head without invoking the context or recipe encoders.
pub(super) fn head(major: u8, value: u64) -> Vec<u8> {
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

/// Encodes literal byte-string fields independently.
pub(super) fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = head(2, value.len() as u64);
    out.extend_from_slice(value);
    out
}

/// Encodes literal UTF-8 fields independently.
pub(super) fn text(value: &str) -> Vec<u8> {
    let mut out = head(3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    out
}

/// Assembles complete ordered tuple fields independently.
pub(super) fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = head(4, values.len() as u64);
    for value in values {
        out.extend_from_slice(value);
    }
    out
}

/// Lists the exact historical vocabulary independently of the compiled registry.
pub(super) fn names(revision: u64) -> Vec<&'static str> {
    let mut names = vec![
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
    if revision >= 2 {
        names.push("index-roots");
    }
    if revision == 3 {
        names.push("index-gaps");
    }
    names.sort_unstable();
    names
}

/// Constructs all expected recorded memo fields, including literal absent selected evidence.
pub(super) fn context(record: &VerifiedCommit, revision: u64, later: &[&str]) -> Vec<u8> {
    let mut later = later.to_vec();
    later.sort_unstable();
    array(&[
        head(0, 3),
        bytes(&record.identity()),
        text(PUBLIC),
        bytes(&array(&[text("preset"), text("any")])),
        vec![0xf6],
        head(0, MINIMUM),
        vec![0xf6],
        array(&[
            bytes(&record.commit().tree),
            head(0, revision),
            array(
                &names(revision)
                    .iter()
                    .map(|name| text(name))
                    .collect::<Vec<_>>(),
            ),
            array(&later.iter().map(|name| text(name)).collect::<Vec<_>>()),
        ]),
    ])
}
