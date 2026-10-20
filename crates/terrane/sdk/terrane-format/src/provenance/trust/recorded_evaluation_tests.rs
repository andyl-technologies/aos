//! Checks explicit caller interpretation against genuinely verified immutable views.
//!
//! The caller association is fixture configuration, not a claim decoded from v3.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::auth::{Authority, Grant, IssuerKey, Request, Token, Verb, Verbs};
use crate::identity::{IdentityKind, TERRANE_V1};
use crate::properties::{selected::Selection, semantics::RecordedContext};
use crate::provenance::{sign, verify};
use crate::refs::{Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance};
use ed25519_dalek::SigningKey;

mod fold;

const MINIMUM: u64 = 262144;

fn issuer_keys() -> Vec<IssuerKey> {
    vec![IssuerKey {
        issuer: "issuer".to_string(),
        key_id: "issuer-key".to_string(),
        public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
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
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
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

fn with_request<T>(action: impl FnOnce(&Request<'_>) -> T) -> T {
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
fn vocabulary(revision: u64) -> Vec<&'static str> {
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
fn uint(value: u64) -> Vec<u8> {
    head(0, value)
}

/// Encodes an independent byte string.
fn bytes(value: &[u8]) -> Vec<u8> {
    let mut result = head(2, value.len() as u64);
    result.extend_from_slice(value);
    result
}

/// Encodes an independent text string.
fn text(value: &str) -> Vec<u8> {
    let mut result = head(3, value.len() as u64);
    result.extend_from_slice(value.as_bytes());
    result
}

/// Joins independently encoded array elements.
fn array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut result = head(4, values.len() as u64);
    for value in values {
        result.extend_from_slice(value);
    }
    result
}

fn map(mut rows: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
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

fn file() -> Vec<u8> {
    map(vec![(uint(1), uint(3)), (uint(5), bytes(b"target"))])
}

fn graft(root: Digest, overrides: &[(&str, Vec<u8>)]) -> Vec<u8> {
    map(vec![
        (uint(1), uint(4)),
        (uint(6), bytes(&root)),
        (uint(7), properties(overrides)),
    ])
}

fn node(entries: &[(&[u8], Vec<u8>)], props: &[(&str, Vec<u8>)]) -> Vec<u8> {
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

fn store(history: &mut VerifiedHistory, wire: Vec<u8>) -> Digest {
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &wire)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    history.insert_tree(root, &[(root, wire)]).unwrap();
    root
}

// Signing authenticates the capability, and verification checks the resulting
// signature again. No fixture sets a verified or admitted history flag.
fn retain_view(history: &mut VerifiedHistory, root: Digest) -> Digest {
    retain_view_with_leaf(history, root, root, b"file")
}

fn retain_view_with_leaf(
    history: &mut VerifiedHistory,
    root: Digest,
    leaf_root: Digest,
    path: &[u8],
) -> Digest {
    let mut unsigned = unsigned_commit();
    unsigned.tree = root;
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
    history.insert_commit(verified).unwrap();
    view
}

fn evaluator(
    history: &VerifiedHistory,
    view: Digest,
    root: Digest,
    revision: u64,
    later: &[&str],
) -> TrustContext {
    let context = RecordedContext::new(revision, 3, later).unwrap();
    let history = history
        .fixture_with_selections(&alloc::collections::BTreeMap::from([(
            view,
            crate::properties::selected::Selection::Recorded(context.clone()),
        )]))
        .unwrap();
    TrustContext::new_with_recorded(
        &history,
        view,
        Selector::preset(Preset::Any),
        "private",
        Some("baseline"),
        Some((view, root, context)),
    )
    .unwrap()
}

fn expected_context(view: Digest, root: Digest, revision: u64, later: &[&str]) -> Vec<u8> {
    let names = vocabulary(revision)
        .iter()
        .map(|name| text(name))
        .collect::<Vec<_>>();
    let mut later = later.to_vec();
    later.sort_unstable();
    let later = later.iter().map(|name| text(name)).collect::<Vec<_>>();
    // The closed preset tuple is literal, not output from its owning encoder.
    array(&[
        uint(3),
        bytes(&view),
        text("private"),
        bytes(&array(&[text("preset"), text("any")])),
        text("baseline"),
        uint(MINIMUM),
        vec![0xf6],
        array(&[bytes(&root), uint(revision), array(&names), array(&later)]),
    ])
}

#[test]
fn recorded_evaluator_binds_verified_view_and_complete_configuration() {
    let mut history = VerifiedHistory::new(MINIMUM);
    // Scalar zero is valid physical property data but invalid active index-roots.
    let root = store(
        &mut history,
        node(&[(b"file", file())], &[("index-roots", uint(0))]),
    );
    let view = retain_view(&mut history, root);
    // The evaluator owns preservation names after caller storage disappears.
    let owned = {
        let later = [String::from("future.z"), String::from("index-roots")];
        let names = later.iter().map(String::as_str).collect::<Vec<_>>();
        evaluator(&history, view, root, 1, &names)
    };
    assert_eq!(
        owned.canonical_context(),
        expected_context(view, root, 1, &["future.z", "index-roots"])
    );
    assert!(owned.accepts_path(b"file"));

    let mut configurations = Vec::new();
    for revision in 1..=3 {
        let later: &[&str] = if revision == 1 {
            &["future.z", "index-roots", "index-gaps"]
        } else if revision == 2 {
            &["future.z", "index-gaps"]
        } else {
            &["future.z"]
        };
        let context = evaluator(&history, view, root, revision, later);
        assert_eq!(context.view_root(), root);
        assert_eq!(
            context.canonical_context(),
            expected_context(view, root, revision, later)
        );
        let decoded = super::context::decode(context.canonical_context()).unwrap();
        assert_eq!(decoded.version, 3);
        assert_eq!(decoded.view, view);
        assert_eq!(decoded.domain, "private");
        assert_eq!(decoded.selector, array(&[text("preset"), text("any")]));
        assert_eq!(decoded.baseline, Some("baseline"));
        assert_eq!(decoded.minimum, MINIMUM);
        assert_eq!(decoded.selected, None);
        let recorded = decoded.recorded.unwrap();
        assert_eq!(recorded.root, root);
        assert_eq!(recorded.revision, revision);
        assert_eq!(recorded.behavioral, vocabulary(revision));
        let mut sorted_later = later.to_vec();
        sorted_later.sort_unstable();
        assert_eq!(recorded.later, sorted_later);
        assert_eq!(context.accepts_path(b"file"), revision == 1);
        assert_eq!(
            context.producer_time(root, b"file"),
            (revision == 1).then_some(100)
        );
        let (location, _) = history.locate_policy_layers(view, b"file").unwrap();
        let candidate = history.entry(&location).unwrap();
        assert_eq!(
            context.accepts_entry(root, b"file", &candidate),
            revision == 1
        );
        assert_eq!(
            context.producer_time_entry(root, b"file", &candidate),
            (revision == 1).then_some(100)
        );
        configurations.push(context.canonical_context().to_vec());
    }
    assert_ne!(configurations[0], configurations[1]);
    assert_ne!(configurations[1], configurations[2]);

    let legacy = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::Any),
        "private",
        Some("baseline"),
    )
    .unwrap();
    let expected_legacy = array(&[
        uint(1),
        bytes(&view),
        text("private"),
        bytes(&array(&[text("preset"), text("any")])),
        text("baseline"),
        uint(MINIMUM),
    ]);
    assert_eq!(legacy.canonical_context(), expected_legacy);
    assert!(!legacy.accepts_path(b"file"));
    // The same checked history and root are independently interpreted. None of
    // the raw later spellings selected revision one or registered themselves.
    assert!(evaluator(&history, view, root, 1, &["index-roots"]).accepts_path(b"file"));
    assert!(!evaluator(&history, view, root, 1, &[]).accepts_path(b"file"));
}

#[test]
fn recorded_evaluator_keeps_one_interpretation_across_graft_prefixes() {
    let mut history = VerifiedHistory::new(MINIMUM);
    let child = store(
        &mut history,
        node(&[(b"file", file())], &[("trust", text("any"))]),
    );
    let middle = store(
        &mut history,
        node(
            &[(b"inner", graft(child, &[("index-roots", uint(0))]))],
            &[("trust", text("any"))],
        ),
    );
    let root = store(
        &mut history,
        node(
            &[
                (b"a", graft(middle, &[("index-roots", uint(0))])),
                (b"b", graft(middle, &[("trust", text("attested"))])),
            ],
            &[("trust", text("any"))],
        ),
    );
    let view = retain_view_with_leaf(&mut history, root, child, b"file");
    let inert = evaluator(&history, view, root, 1, &["index-roots"]);
    let active = evaluator(&history, view, root, 2, &[]);
    assert!(inert.accepts_path(b"a/inner/file"));
    assert!(!inert.accepts_path(b"b/inner/file"));
    assert!(!active.accepts_path(b"a/inner/file"));
    assert!(!active.accepts_path(b"b/inner/file"));
    assert_eq!(inert.producer_time(root, b"a/inner/file"), Some(100));
    assert_eq!(active.producer_time(root, b"a/inner/file"), None);
    assert!(!inert.accepts(child, b"file"));
    assert!(!inert.accepts_path(b"missing/inner/file"));
    let (location, layers) = history.locate_policy_layers(view, b"a/inner/file").unwrap();
    assert_eq!(location.root, child);
    assert_eq!(layers.len(), 3);
    assert_eq!(layers[1].occurrence, b"a");
    assert_eq!(layers[2].occurrence, b"a/inner");
    assert_eq!(layers[2].overrides.as_ref().unwrap()[0].value, uint(0));

    // A descendant's permissive selector cannot undo a signed ancestor refusal.
    let restricted = store(
        &mut history,
        node(
            &[(b"a", graft(middle, &[("trust", text("any"))]))],
            &[("trust", text("attested"))],
        ),
    );
    let restricted_view = retain_view_with_leaf(&mut history, restricted, child, b"file");
    assert!(
        !evaluator(&history, restricted_view, restricted, 1, &["index-roots"])
            .accepts_path(b"a/inner/file")
    );

    // A strict root consults the caller baseline until a signed root supplies
    // its own baseline. The permissive child does not replace that ancestor.
    let strict_root = store(
        &mut history,
        node(&[(b"a", graft(child, &[]))], &[("trust", text("strict"))]),
    );
    let strict_view = retain_view_with_leaf(&mut history, strict_root, child, b"file");
    let strict_history = history
        .fixture_with_selections(&BTreeMap::from([(
            strict_view,
            Selection::Recorded(RecordedContext::new(1, 3, &[]).unwrap()),
        )]))
        .unwrap();
    for (baseline, expected) in [
        (Some("baseline"), true),
        (Some("other"), false),
        (None, false),
    ] {
        let context = TrustContext::new_with_recorded(
            &strict_history,
            strict_view,
            Selector::preset(Preset::Any),
            "private",
            baseline,
            Some((
                strict_view,
                strict_root,
                RecordedContext::new(1, 3, &[]).unwrap(),
            )),
        )
        .unwrap();
        assert_eq!(context.accepts_path(b"a/file"), expected);
    }
    let overridden = store(
        &mut history,
        node(
            &[(b"a", graft(child, &[]))],
            &[("baseline", text("baseline")), ("trust", text("strict"))],
        ),
    );
    let overridden_view = retain_view_with_leaf(&mut history, overridden, child, b"file");
    let overridden_history = history
        .fixture_with_selections(&BTreeMap::from([(
            overridden_view,
            Selection::Recorded(RecordedContext::new(1, 3, &[]).unwrap()),
        )]))
        .unwrap();
    let context = TrustContext::new_with_recorded(
        &overridden_history,
        overridden_view,
        Selector::preset(Preset::Any),
        "private",
        Some("other"),
        Some((
            overridden_view,
            overridden,
            RecordedContext::new(1, 3, &[]).unwrap(),
        )),
    )
    .unwrap();
    assert!(context.accepts_path(b"a/file"));
}

#[test]
fn recorded_evaluator_refuses_missing_or_inconsistent_association() {
    let mut history = VerifiedHistory::new(MINIMUM);
    let root = store(&mut history, node(&[(b"file", file())], &[]));
    let view = retain_view(&mut history, root);
    let mut unauthenticated = history.commit(&view).unwrap().commit().clone();
    unauthenticated.signature = None;
    assert!(with_request(|request| verify(&unauthenticated, &issuer_keys(), request, 4)).is_err());
    let recorded = RecordedContext::new(3, 3, &[]).unwrap();
    for association in [
        None,
        Some(([0; 32], root, recorded.clone())),
        Some((view, [0; 32], recorded.clone())),
    ] {
        assert!(
            TrustContext::new_with_recorded(
                &history,
                view,
                Selector::preset(Preset::Any),
                "private",
                None,
                association
            )
            .is_err()
        );
    }
    assert!(
        TrustContext::new_with_recorded(
            &history,
            [0; 32],
            Selector::preset(Preset::Any),
            "private",
            None,
            Some(([0; 32], root, recorded.clone()))
        )
        .is_err()
    );
    assert!(
        TrustContext::new_with_recorded(
            &VerifiedHistory::new(MINIMUM),
            view,
            Selector::preset(Preset::Any),
            "private",
            None,
            Some((view, root, recorded.clone()))
        )
        .is_err()
    );
    assert!(RecordedContext::new(0, 3, &[]).is_err());
    assert!(RecordedContext::new(4, 3, &[]).is_err());
    assert!(RecordedContext::new(1, 3, &["index-roots", "index-roots"]).is_err());
    assert!(RecordedContext::new(3, 3, &["index-roots"]).is_err());
    // Explicit current interpretation uses v3 even when no historical names exist.
    let current = evaluator(&history, view, root, 3, &[]);
    assert!(current.accepts_path(b"file"));
    assert_eq!(
        current.canonical_context(),
        expected_context(view, root, 3, &[])
    );
    let shared = TrustContext::from_shared_with_recorded(
        Rc::new(
            history
                .fixture_with_selections(&BTreeMap::from([(
                    view,
                    Selection::Recorded(recorded.clone()),
                )]))
                .unwrap(),
        ),
        view,
        Selector::preset(Preset::Any),
        "private",
        Some("baseline"),
        Some((view, root, recorded.clone())),
    )
    .unwrap();
    assert_eq!(shared.canonical_context(), current.canonical_context());

    // Equal current behavior retains different legacy/explicit memo bytes.
    let legacy = TrustContext::new(
        &history,
        view,
        Selector::preset(Preset::Any),
        "private",
        Some("baseline"),
    )
    .unwrap();
    assert!(legacy.accepts_path(b"file"));
    assert_ne!(legacy.canonical_context(), current.canonical_context());

    use crate::algebra::{MergePolicy, Recipe};
    let other_root = store(&mut history, node(&[(b"other", file())], &[]));
    let other_view = retain_view_with_leaf(&mut history, other_root, other_root, b"other");
    let ours = evaluator(&history, view, root, 3, &[]);
    let theirs = evaluator(&history, other_view, other_root, 1, &["future.value"]);
    let policy =
        crate::algebra::TrustContext::from_verified(vec![ours.clone(), theirs.clone()]).unwrap();
    let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
    let recipe = Recipe::Merge {
        base: root,
        ours: root,
        theirs: other_root,
        policies: &policies,
        trust: &policy,
        domains: None,
    };
    let wire = recipe.encode();
    let identity = recipe.identity().unwrap();
    let decoded = Recipe::decode(&wire).unwrap();
    assert_eq!(decoded.as_recipe().encode(), wire);
    assert_eq!(decoded.as_recipe().identity().unwrap(), identity);
    let rebound = Recipe::decode(&wire)
        .unwrap()
        .bind_verified(vec![
            evaluator(&history, view, root, 3, &[]),
            evaluator(&history, other_view, other_root, 1, &["future.value"]),
        ])
        .unwrap();
    assert_eq!(rebound.as_recipe().encode(), wire);
    assert_eq!(rebound.as_recipe().identity().unwrap(), identity);
    assert!(
        Recipe::decode(&wire)
            .unwrap()
            .bind_verified(vec![theirs.clone(), ours.clone()])
            .is_err()
    );
    assert!(
        Recipe::decode(&wire)
            .unwrap()
            .bind_verified(vec![
                evaluator(&history, view, root, 3, &["future.changed"]),
                theirs.clone(),
            ])
            .is_err()
    );
    let legacy_pair = vec![
        TrustContext::new(
            &history,
            view,
            Selector::preset(Preset::Any),
            "private",
            Some("baseline"),
        )
        .unwrap(),
        TrustContext::new(
            &history,
            other_view,
            Selector::preset(Preset::Any),
            "private",
            Some("baseline"),
        )
        .unwrap(),
    ];
    assert!(
        Recipe::decode(&wire)
            .unwrap()
            .bind_verified(legacy_pair.clone())
            .is_err()
    );
    let legacy_policy = crate::algebra::TrustContext::from_verified(legacy_pair).unwrap();
    let legacy_recipe = Recipe::Merge {
        base: root,
        ours: root,
        theirs: other_root,
        policies: &policies,
        trust: &legacy_policy,
        domains: None,
    };
    assert_ne!(legacy_recipe.encode(), wire);
    assert_ne!(legacy_recipe.identity().unwrap(), identity);
    // Even a matching configuration cannot bind to different recipe operands.
    let wrong_operands = Recipe::Merge {
        base: root,
        ours: other_root,
        theirs: root,
        policies: &policies,
        trust: &policy,
        domains: None,
    };
    assert!(
        Recipe::decode(&wrong_operands.encode())
            .unwrap()
            .bind_verified(vec![ours, theirs])
            .is_err()
    );
}
