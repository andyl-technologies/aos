//! Constructs complete ordinary signed histories and independent primitive models.
//!
//! Every record is actually reverified. Configuration is separately supplied
//! fixture data; no protected native authority or checked flags are fabricated.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use super::*;
use crate::identity::{IdentityKind, TERRANE_V1};
use crate::properties::semantics::{
    RecordedContext,
    associations::{RecordedAssociation, RecordedAssociations},
};

/// Enumerates the frozen revision-one vocabulary independently of the registry.
pub(super) const LEGACY: &[&str] = &[
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

/// Supplies an independently enumerated fixed behavioral fence.
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

/// Retains genuine source evidence separately from the destination-only history.
pub(super) struct RecordedFixture {
    /// Actual independently verified private source history and signed witness.
    pub source: Fixture,
    /// Destination history containing actual finalized signed metadata only.
    pub history: VerifiedHistory,
    /// Actual final destination Commit verified against issuer keys and claims.
    pub commit: VerifiedCommit,
    /// Physical root carrying the certified file, shared by repeated occurrences.
    pub leaf: Digest,
}

/// Encodes primitive unsigned integers without a format-specific encoder.
pub(super) fn uint(value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    cbor::write_uint(&mut output, value);
    output
}

/// Encodes primitive bytes without a format-specific encoder.
pub(super) fn bytes(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    cbor::write_bytes(&mut output, value);
    output
}

/// Encodes primitive text without a format-specific encoder.
pub(super) fn text(value: &str) -> Vec<u8> {
    let mut output = Vec::new();
    cbor::write_text(&mut output, value);
    output
}

/// Joins complete independently specified array slots.
pub(super) fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut output = Vec::new();
    cbor::write_array(&mut output, values.len());
    for value in values {
        output.extend_from_slice(value);
    }
    output
}

/// Joins complete primitive map fields in encoded-byte lexicographic order.
pub(super) fn map(mut values: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    values.sort_by(|left, right| left.0.cmp(&right.0));
    let mut output = Vec::new();
    cbor::write_map(&mut output, values.len());
    for (key, value) in values {
        output.extend(key);
        output.extend(value);
    }
    output
}

/// Supplies literal preserve-only registrations independently of Node spelling.
pub(super) fn later(revision: u64) -> &'static [&'static str] {
    match revision {
        1 => &["index-roots", "index-gaps"],
        2 => &["index-gaps"],
        _ => &[],
    }
}

/// Retains exact independent configuration for a genuinely checked immutable pair.
///
/// # Panics
/// Panics if a literal revision or preservation vocabulary is invalid.
pub(super) fn association(
    record: &VerifiedCommit,
    revision: u64,
    later: &[&str],
) -> RecordedAssociation {
    RecordedAssociation::new(
        record.identity(),
        record.commit().tree,
        RecordedContext::new(revision, 3, later).unwrap(),
    )
}

/// Copies one explicit association into an ordinary immutable table.
///
/// # Panics
/// Panics if the singleton ordinary configuration is inconsistent.
pub(super) fn table(
    record: &VerifiedCommit,
    revision: u64,
    later: &[&str],
) -> RecordedAssociations {
    RecordedAssociations::new([association(record, revision, later)]).unwrap()
}

/// Authenticates finalized Commit bytes independently after the real signing API.
///
/// # Panics
/// Panics if the actual finalized signature/token/original claimed context fails.
pub(super) fn reverified(record: VerifiedCommit) -> VerifiedCommit {
    let roots: Vec<_> = record
        .commit()
        .profile_pair
        .commit_context
        .as_ref()
        .unwrap()
        .roots()
        .iter()
        .map(|root| RequestRoot {
            path: root.path(),
            domain: root.domain(),
        })
        .collect();
    let checked = verify_history(
        record.commit(),
        &issuer_keys(),
        &roots,
        &[("refs/heads/main", 4)],
    )
    .unwrap();
    assert_eq!(record.identity(), checked.identity());
    checked
}

/// Signs the independently assembled registered statement for finalized metadata.
///
/// The source introduction is checked through genuine source history. This
/// test-only primitive model avoids the current-only production issuance helper;
/// it grants no native issuance or current-operation authority.
///
/// # Panics
/// Panics if actual source evidence, finalized typed receipts or projection fail.
pub(super) fn certify(source: &Fixture, mut commit: Commit) -> VerifiedCommit {
    let binding = disclosure_target_binding(&commit).unwrap();
    for receipt in commit.profile_pair.entry_receipts.as_mut().unwrap() {
        let Some(proof) = receipt.disclosure_proof.as_mut() else {
            continue;
        };
        let origin = receipt.reintroduced_from.as_ref().unwrap();
        let actual = EntryLocation {
            commit: origin.commit,
            root: origin.root,
            path: origin.path.clone(),
        };
        let introduced = source.source.introducing_commit(&actual).unwrap();
        assert_eq!(introduced, source.source_commit.identity());
        let projection = array(&[uint(1), uint(3), array(&[uint(0), bytes(&[31; 32])])]);
        let statement = array(&[
            text(&proof.authority_key),
            text(&proof.source_domain),
            uint(proof.observed_at),
            array(&[
                bytes(&origin.commit),
                bytes(&origin.root),
                bytes(&origin.path),
            ]),
            bytes(&introduced),
            array(&[
                text("refs/heads/main"),
                bytes(&receipt.root),
                bytes(&receipt.path),
                text(PUBLIC),
            ]),
            projection,
            bytes(&binding),
        ]);
        let mut preimage = b"terrane-disclosure-proof-v1\0".to_vec();
        preimage.extend(statement);
        proof.signature = SigningKey::from_bytes(&AUTHORITY_SECRET)
            .sign(&preimage)
            .to_bytes();
    }
    reverified(authored(commit, PUBLIC, &[11; 32], false))
}

/// Supplies raw public policy with deliberately inert newer structural metadata.
pub(super) fn properties(revision: u64) -> Vec<Property<'static>> {
    let mut values = vec![
        Property {
            name: "domain",
            value: b"\x66public",
        },
        Property {
            name: "trust",
            value: b"\x63any",
        },
    ];
    if revision < 3 {
        values.push(Property {
            name: "index-gaps",
            value: &[0],
        });
    }
    if revision == 1 {
        values.push(Property {
            name: "index-roots",
            value: &[0],
        });
    }
    values.sort_by_key(|property| property.name);
    values
}

/// Constructs a genuine repeated nested destination without its private source graph.
///
/// # Panics
/// Panics if canonical trees, real signing, independently signed certificates,
/// or actual original-context verification fail.
pub(super) fn fixture_recorded(revision: u64, nested: bool) -> RecordedFixture {
    let source = fixture(file());
    let original = bytes(&source.source_commit.identity());
    let mut disclosed = file();
    disclosed.attrs.push(Attribute {
        name: "provenance.reintroduced-from",
        value: &original,
    });
    disclosed.attrs_present = true;
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    let (leaf, leaf_bytes) = tree(vec![item(b"file", disclosed)], Some(properties(revision)));
    history.insert_tree(leaf, &[(leaf, leaf_bytes)]).unwrap();
    let mut receipts = vec![receipt(leaf, EntryOrigin::Current)];
    let cert = &mut receipts[0];
    cert.reintroduced_from = Some(EntrySource {
        commit: source.source_commit.identity(),
        root: source.source_root,
        path: b"file".to_vec(),
    });
    cert.attributes = Some(vec![(
        "provenance.reintroduced-from".to_string(),
        EntryOrigin::Current,
    )]);
    cert.disclosure_proof = Some(DisclosureProof {
        authority_key: crate::provenance::disclosure::key_name(&authority().public_key),
        source_domain: SOURCE_DOMAIN.to_string(),
        observed_at: 100,
        signature: [0; 64],
    });
    let root = if nested {
        let mut graft = entry(b"");
        graft.kind = EntryKind::Tree {
            root: leaf,
            props: None,
        };
        let (middle, middle_bytes) = tree(vec![item(b"inner", graft)], Some(properties(revision)));
        history
            .insert_tree(middle, &[(middle, middle_bytes)])
            .unwrap();
        let mut middle_receipt = receipt(middle, EntryOrigin::Current);
        middle_receipt.path = b"inner".to_vec();
        receipts.push(middle_receipt);
        let mut graft = entry(b"");
        graft.kind = EntryKind::Tree {
            root: middle,
            props: Some(vec![Property {
                name: "trust",
                value: b"\x63any",
            }]),
        };
        let (root, root_bytes) = tree(
            vec![item(b"a", graft.clone()), item(b"b", graft)],
            Some(properties(revision)),
        );
        history.insert_tree(root, &[(root, root_bytes)]).unwrap();
        for path in [b"a", b"b"] {
            let mut current = receipt(root, EntryOrigin::Current);
            current.path = path.to_vec();
            receipts.push(current);
        }
        root
    } else {
        leaf
    };
    receipts.sort_by(|left, right| (&left.root, &left.path).cmp(&(&right.root, &right.path)));
    let mut commit = unsigned_commit();
    commit.tree = root;
    commit.message = "recorded destination".to_string();
    commit.profile_pair.entry_receipts = Some(receipts);
    // All fields and original root claims are finalized before certificate binding.
    let prototype = reverified(authored(commit, PUBLIC, &[11; 32], false));
    let commit = certify(&source, prototype.commit().clone());
    history
        .insert_commit_selected(
            commit.clone(),
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(revision, 3, later(revision)).unwrap(),
            ),
        )
        .unwrap();
    RecordedFixture {
        source,
        history,
        commit,
        leaf,
    }
}

/// Completes actual recorded verification with independent original bootstrap input.
///
/// # Errors
/// Returns the production candidate, certificate, origin or original-scope refusal.
///
/// # Panics
/// Panics if the literal interpretation is invalid before candidate construction.
pub(super) fn finish(
    fixture: &RecordedFixture,
    revision: u64,
    later: &[&str],
) -> Result<(VerifiedHistory, VerifiedDisclosureBatch), Rejected> {
    let input = table(&fixture.commit, revision, later);
    DisclosureCandidate::new_with_recorded_properties_and_bootstrap(
        &fixture.history,
        fixture.commit.identity(),
        &[authority()],
        defaults(),
        Some(&input),
        fixture_bootstrap().authority,
        fixture_bootstrap(),
    )?
    .finish()
}

/// Constructs an actual recorded evaluator after genuine candidate completion.
///
/// # Panics
/// Panics if independently supplied interpretation differs from checked scope.
pub(super) fn evaluator(
    history: &VerifiedHistory,
    record: &VerifiedCommit,
    revision: u64,
    later: &[&str],
) -> TrustContext {
    TrustContext::new_with_recorded(
        history,
        record.identity(),
        Selector::preset(Preset::Any),
        PUBLIC,
        Some("baseline"),
        Some((
            record.identity(),
            record.commit().tree,
            RecordedContext::new(revision, 3, later).unwrap(),
        )),
    )
    .unwrap()
}

/// Independently specifies every legacy or recorded immutable context slot.
pub(super) fn context(record: &VerifiedCommit, revision: Option<u64>, later: &[&str]) -> Vec<u8> {
    let selector = array(&[text("preset"), text("any")]);
    let mut fields = vec![
        uint(if revision.is_some() { 3 } else { 1 }),
        bytes(&record.identity()),
        text(PUBLIC),
        bytes(&selector),
        text("baseline"),
        uint(MIN_CHUNK),
    ];
    if let Some(revision) = revision {
        let mut later = later.to_vec();
        later.sort_unstable();
        fields.push(vec![0xf6]);
        fields.push(array(&[
            bytes(&record.commit().tree),
            uint(revision),
            array(
                &vocabulary(revision)
                    .into_iter()
                    .map(text)
                    .collect::<Vec<_>>(),
            ),
            array(&later.into_iter().map(text).collect::<Vec<_>>()),
        ]));
    }
    array(&fields)
}

/// Assembles every enclosing merge/trust/configuration field and raw memo preimage.
///
/// # Panics
/// Panics if the registered memo descriptor rejects the complete primitive model
/// or its digest differs from the independently assembled raw preimage.
pub(super) fn recipe(
    record: &VerifiedCommit,
    contexts: &[Vec<u8>; 2],
) -> (Vec<u8>, Vec<u8>, Digest) {
    let configuration = array(&[
        array(
            &contexts
                .iter()
                .map(|value| bytes(value))
                .collect::<Vec<_>>(),
        ),
        vec![0xf6],
    ]);
    let trust = map(vec![
        (uint(1), array(&[text("preset"), text("any")])),
        (uint(2), text("terrane-verified-path/v1")),
        (uint(3), configuration),
        (uint(4), array(&[])),
    ]);
    let recipe = map(vec![
        (uint(1), text("merge")),
        (
            uint(2),
            array(&[
                bytes(&record.commit().tree),
                bytes(&record.commit().tree),
                bytes(&record.commit().tree),
            ]),
        ),
        (
            uint(3),
            map(vec![
                (
                    text("policy"),
                    array(&[text("prefer-trusted"), text("keep-conflict")]),
                ),
                (text("trust"), trust),
            ]),
        ),
    ]);
    let mut preimage = b"terrane-memo-v1\0".to_vec();
    preimage.extend_from_slice(&recipe);
    let key = *blake3::hash(&preimage).as_bytes();
    assert_eq!(
        TERRANE_V1
            .calculate(IdentityKind::Memo, &recipe)
            .unwrap()
            .terrane_v1_digest()
            .unwrap(),
        key
    );
    (recipe, preimage, key)
}

/// Identifies an independently present private edge in a complete retained record.
#[derive(Clone, Copy, Debug)]
pub(super) enum PrivateRetention {
    /// An unrelated canonical child root has a private effective domain.
    SiblingGraft,
    /// An ordinary signed parent retains the private original record.
    OrdinaryAncestor,
    /// A sibling receipt carries a private source independently of selected data.
    UnselectedOrigin,
}

/// Builds a genuinely checked public view with a separately verified private edge.
///
/// # Panics
/// Panics if literal canonical evidence, real original signatures or selected
/// scope verification fail before the complete-retention refusal is exercised.
pub(super) fn retained_private(
    source: &Fixture,
    edge: PrivateRetention,
) -> (VerifiedHistory, VerifiedCommit) {
    let mut history = VerifiedHistory::new(MIN_CHUNK);
    history
        .insert_tree(
            source.source_root,
            &[(source.source_root, source.source_bytes.clone())],
        )
        .unwrap();
    history
        .insert_commit_selected(
            reverified(source.source_commit.clone()),
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(3, 3, &[]).unwrap(),
            ),
        )
        .unwrap();
    super::check_scope(&mut history, &source.source_commit, 3, &[]);
    let mut entries = vec![item(b"other", file())];
    let mut claims = vec![RequestRoot {
        path: b"/",
        domain: PUBLIC,
    }];
    let mut commit = unsigned_commit();
    match edge {
        PrivateRetention::SiblingGraft => {
            let mut graft = entry(b"");
            graft.kind = EntryKind::Tree {
                root: source.source_root,
                props: None,
            };
            entries.push(item(b"vault", graft));
            claims.push(RequestRoot {
                path: b"/vault",
                domain: SOURCE_DOMAIN,
            });
        }
        PrivateRetention::OrdinaryAncestor => {
            commit.parents = vec![source.source_commit.identity()];
            claims.push(RequestRoot {
                path: b"/",
                domain: SOURCE_DOMAIN,
            });
        }
        PrivateRetention::UnselectedOrigin => {
            entries.insert(0, item(b"hidden", file()));
        }
    }
    let (root, bytes) = tree(entries, Some(properties(3)));
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut other = receipt(root, EntryOrigin::Current);
    other.path = b"other".to_vec();
    let mut receipts = vec![other];
    match edge {
        PrivateRetention::SiblingGraft => {
            let mut vault = receipt(root, EntryOrigin::Current);
            vault.path = b"vault".to_vec();
            receipts.push(vault);
        }
        PrivateRetention::UnselectedOrigin => {
            let mut hidden = receipt(
                root,
                EntryOrigin::Source(EntrySource {
                    commit: source.source_commit.identity(),
                    root: source.source_root,
                    path: b"file".to_vec(),
                }),
            );
            hidden.path = b"hidden".to_vec();
            receipts.insert(0, hidden);
        }
        PrivateRetention::OrdinaryAncestor => {}
    }
    commit.tree = root;
    commit.profile_pair.entry_receipts = Some(receipts);
    let record = reverified(authored_claims(commit, &claims, &[9; 32], true));
    history
        .insert_commit_selected(
            record.clone(),
            crate::properties::selected::Selection::Recorded(
                RecordedContext::new(3, 3, &[]).unwrap(),
            ),
        )
        .unwrap();
    super::check_scope(&mut history, &record, 3, &[]);
    assert_eq!(
        history.introducing_commit(&EntryLocation {
            commit: record.identity(),
            root,
            path: b"other".to_vec()
        }),
        Ok(record.identity())
    );
    (history, record)
}

/// Signs finalized metadata at an actual owner or a distinct graft occurrence.
///
/// # Panics
/// Panics if the canonical metadata, actual certificate or final Commit cannot
/// be encoded and genuinely reverified.
pub(super) fn namespace_metadata(
    fixture: &RecordedFixture,
    name: &str,
    value: &[u8],
    on_graft: bool,
) -> (VerifiedHistory, VerifiedCommit) {
    let mut mounted = entry(b"");
    mounted.kind = EntryKind::Tree {
        root: fixture.leaf,
        props: on_graft.then(|| vec![Property { name, value }]),
    };
    let mut properties = properties(3);
    if !on_graft {
        properties.push(Property { name, value });
    }
    let (root, bytes) = tree(vec![item(b"docs", mounted)], Some(properties));
    let mut history = fixture.history.clone();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = fixture.commit.commit().clone();
    commit.tree = root;
    let mut graft_receipt = receipt(root, EntryOrigin::Current);
    graft_receipt.path = b"docs".to_vec();
    commit
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .push(graft_receipt);
    commit
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .sort_by(|left, right| (&left.root, &left.path).cmp(&(&right.root, &right.path)));
    let signed = certify(&fixture.source, commit);
    history
        .insert_commit_selected(
            signed.clone(),
            history
                .property_selection(fixture.commit.identity())
                .unwrap(),
        )
        .unwrap();
    (history, signed)
}
