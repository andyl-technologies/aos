//! Independently checks contextual state ordering and explicit auxiliary roles.
//!
//! Native witnesses use genuinely signed publication and the held metadata
//! adapter, keeping catalog inspection separate from semantic reachability.

use super::*;
use terrane_format::gc::Phase;
use terrane_format::indexing::carrier::SemanticContext;
use terrane_format::indexing::evaluation::IndexData;

/// Names assertion failures without disabling the workspace's unwrap lint.
trait AssertSuccess {
    type Value;

    #[track_caller]
    fn assert_success(self) -> Self::Value;
}

impl<T, E: std::fmt::Debug> AssertSuccess for Result<T, E> {
    type Value = T;

    #[track_caller]
    fn assert_success(self) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("expected success, observed {error:?}"),
        }
    }
}

impl<T> AssertSuccess for Option<T> {
    type Value = T;

    #[track_caller]
    fn assert_success(self) -> T {
        match self {
            Some(value) => value,
            None => panic!("expected present value"),
        }
    }
}

#[cfg(all(feature = "tokio", unix))]
trait AssertFailure {
    type Error;

    #[track_caller]
    fn assert_failure(self) -> Self::Error;
}

#[cfg(all(feature = "tokio", unix))]
impl<T: std::fmt::Debug, E> AssertFailure for Result<T, E> {
    type Error = E;

    #[track_caller]
    fn assert_failure(self) -> E {
        match self {
            Err(error) => error,
            Ok(value) => panic!("expected failure, observed {value:?}"),
        }
    }
}

fn state() -> GcState {
    GcState {
        cycle: 1,
        epoch: 2,
        phase: Phase::Mark,
        snapshot_at: 3,
        checkpoints: Vec::new(),
        pending: vec![pending(ParentCutoff::RootsOnly)],
        expanded: Vec::new(),
        progress: Vec::new(),
        objects: Vec::new(),
    }
}

fn pending(cutoff: ParentCutoff) -> Pending {
    Pending {
        kind: 3,
        hash: [1; 32],
        parent_cutoff: cutoff,
        flags: 0,
        proof_context: None,
    }
}

fn context(path: &[u8]) -> ProofContext {
    ProofContext::new([1; 32], [2; 32], path.to_vec()).assert_success()
}

fn occurrence(root: Digest, path: &[u8]) -> history::Occurrence {
    history::Occurrence {
        context: ProofContext::new([1; 32], root, path.to_vec()).assert_success(),
        domain: "public".into(),
        revisions: crate::indexing::SemanticRevisions {
            property: 3,
            attribute: 2,
            tree: 1,
        },
        usage: terrane_format::tree_format::TreeUse::Ordinary,
        nodes: vec![(root, true)],
        bindings: Vec::new(),
        files: Vec::new(),
    }
}

#[test]
fn common_walk_cutoffs_remain_per_occurrence_and_broadest() {
    let mut contexts = vec![ExpandedContext {
        commit: [1; 32],
        parent_cutoff: ParentCutoff::Since(7),
        proof_context: Some(context(b"/a")),
    }];
    for (path, cutoff) in [
        (b"/a".as_slice(), ParentCutoff::Since(8)),
        (b"/b", ParentCutoff::RootsOnly),
        (b"/a", ParentCutoff::Since(6)),
        (b"/b", ParentCutoff::Unbounded),
    ] {
        merge_context(
            &mut contexts,
            ExpandedContext {
                commit: [1; 32],
                parent_cutoff: cutoff,
                proof_context: Some(context(path)),
            },
        );
    }
    assert_eq!(
        contexts,
        vec![
            ExpandedContext {
                commit: [1; 32],
                parent_cutoff: ParentCutoff::Since(6),
                proof_context: Some(context(b"/a"))
            },
            ExpandedContext {
                commit: [1; 32],
                parent_cutoff: ParentCutoff::Unbounded,
                proof_context: Some(context(b"/b"))
            },
        ]
    );
}

#[test]
fn common_walk_witness_and_legacy_rows_do_not_cover_full_present_context() {
    let mut current = state();
    current.expanded.push(ExpandedContext {
        commit: [1; 32],
        parent_cutoff: ParentCutoff::Unbounded,
        proof_context: None,
    });
    current.objects.push(ExpandedObject {
        kind: 3,
        hash: [1; 32],
        flags: 8,
        proof_context: Some(context(b"/a")),
    });
    assert!(covered(
        &current,
        &pending(ParentCutoff::RootsOnly),
        &context(b"/a"),
        VisitMode::Witness
    ));
    assert!(!covered(
        &current,
        &pending(ParentCutoff::RootsOnly),
        &context(b"/a"),
        VisitMode::Full
    ));
    assert!(!covered(
        &current,
        &pending(ParentCutoff::RootsOnly),
        &context(b"/b"),
        VisitMode::Witness
    ));
}

#[test]
fn common_walk_context_order_is_fieldwise_and_round_trips_exact_state() {
    let mut current = state();
    let mut marks = BTreeSet::new();
    let mut expansion = Expansion::default();
    for path in [Some(b"/z".as_slice()), None, Some(b"/aa".as_slice())] {
        expansion.complete(
            &pending(ParentCutoff::RootsOnly),
            path.map(context),
            VisitMode::Full,
        );
    }
    expansion.apply(&mut current, &mut marks);
    let expected = [None, Some(context(b"/aa")), Some(context(b"/z"))];
    assert_eq!(
        current
            .expanded
            .iter()
            .map(|row| row.proof_context.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        GcState::decode(&current.encode().assert_success()).assert_success(),
        current
    );
}

#[test]
fn common_walk_selects_complete_graft_key_and_refuses_forged_position() {
    let occurrences = [
        occurrence([2; 32], b"/"),
        occurrence([3; 32], b"/a"),
        occurrence([4; 32], b"/a/x/y"),
        occurrence([5; 32], b"/ab"),
    ];
    let selected = history::select(&occurrences, Some(&occurrences[1].context)).assert_success();
    assert_eq!(
        selected
            .iter()
            .map(|item| item.context.absolute_path())
            .collect::<Vec<_>>(),
        vec![b"/a".as_slice(), b"/a/x/y"]
    );
    let forged = ProofContext::new([9; 32], [3; 32], b"/a".to_vec()).assert_success();
    assert!(history::select(&occurrences, Some(&forged)).is_err());
}

#[test]
fn common_walk_empty_physical_node_keeps_ordinary_and_index_roles_distinct() {
    // Literal canonical Node {1:0,2:[]}; no production tree/index constructor.
    let bytes = vec![0xa2, 0x01, 0x00, 0x02, 0x80];
    let mut hash = blake3::Hasher::new();
    hash.update(b"terrane-node-v1\0");
    hash.update(&bytes);
    let root = *hash.finalize().as_bytes();
    let occurrence = occurrence(root, b"/");
    let data = IndexData {
        root,
        nodes: BTreeMap::from([(root, bytes)]),
        work: Default::default(),
    };
    let mut expansion = Expansion::default();
    expansion.object(2, root, 2, &occurrence.context);
    indexes::record_closure(
        &data,
        SemanticContext::new(3, 2, 1).assert_success(),
        262144,
        &occurrence,
        VisitMode::Full,
        &mut expansion,
    )
    .assert_success();
    expansion.objects.sort();
    assert_eq!(
        expansion.objects,
        vec![
            ExpandedObject {
                kind: 2,
                hash: root,
                flags: 2,
                proof_context: Some(occurrence.context.clone())
            },
            ExpandedObject {
                kind: 2,
                hash: root,
                flags: 6,
                proof_context: Some(occurrence.context)
            },
        ]
    );
    assert_eq!(expansion.marks, BTreeSet::from([root]));
}

#[cfg(all(feature = "tokio", unix))]
mod native;

#[test]
fn common_walk_certificates_apply_only_to_direct_entry_objects() {
    let occurrence = occurrence([2; 32], b"/graft");
    let mut file = history::File {
        content: terrane_format::tree_format::ContentRef::Manifest([3; 32]),
        dictionaries: vec![[5; 32]],
        location: terrane_format::provenance::EntryLocation {
            commit: [1; 32],
            root: [2; 32],
            path: b"nested/file".to_vec(),
        },
    };
    let direct_manifest = attributes::Target::entry(&occurrence, &file);
    let member = attributes::Target::manifest_member([4; 32], &occurrence, &file);
    let dictionary = attributes::Target::dictionary([5; 32], &occurrence, &file);
    let metadata = attributes::Target::metadata([3; 32], &occurrence);

    assert!(direct_manifest.certificate_eligible());
    assert!(!member.certificate_eligible());
    assert!(!dictionary.certificate_eligible());
    assert!(!metadata.certificate_eligible());
    assert!(direct_manifest != metadata);

    // A hash collision or repeated use cannot change the independently declared
    // edge's role into the exact ContentRef edge certified at this location.
    let equal_digest_member = attributes::Target::manifest_member([3; 32], &occurrence, &file);
    let equal_digest_dictionary = attributes::Target::dictionary([3; 32], &occurrence, &file);
    assert!(!equal_digest_member.certificate_eligible());
    assert!(!equal_digest_dictionary.certificate_eligible());
    assert!(direct_manifest != equal_digest_member);
    assert!(direct_manifest != equal_digest_dictionary);

    file.content = terrane_format::tree_format::ContentRef::Inline([6; 32]);
    assert!(attributes::Target::entry(&occurrence, &file).certificate_eligible());
}
