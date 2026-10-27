//! Validates graft overrides through genuine admission, publication and rollback.

use super::*;
use crate::store::ContentStore;
use std::collections::BTreeMap;
use terrane_format::auth::{Attenuation, Grant, Token, Verb, Verbs};
use terrane_format::identity::TERRANE_V1;

const PRESERVED: &[&str] = &["index-roots", "index-gaps", "future-note"];
const WRITER_ADMIN: &[u8] = b"\x81\x82\x66writer\x18\x1f";
const WRITER_COMMIT: &[u8] = b"\x81\x82\x66writer\x04";
const WIDER: &[u8] = b"\x82\x82\x66writer\x18\x1f\x82\x63new\x04";

fn request(
    parents: Vec<Digest>,
    overrides: &[Property<'_>],
    child_acl: Option<&[u8]>,
) -> TestResult<CommitRequest> {
    let child = Tree::build(
        Vec::new(),
        child_acl.map(|value| vec![Property { name: "acl", value }]),
        262144,
        TreeUse::Ordinary,
    )?;
    let entries = [
        (b"a".as_slice(), b"\x67forever".as_slice()),
        (b"b".as_slice(), b"\x62gc".as_slice()),
    ]
    .into_iter()
    .map(|(key, retain)| {
        let mut props = overrides.to_vec();
        props.push(Property {
            name: "retain",
            value: retain,
        });
        LeafItem {
            key: key.to_vec(),
            entry: Entry {
                kind: EntryKind::Tree {
                    root: child.root_identity(),
                    props: Some(props),
                },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None,
            },
        }
    })
    .collect();
    let root = Tree::build(
        entries,
        Some(vec![
            Property {
                name: "acl",
                value: WRITER_ADMIN,
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )?;
    let mut request = crate::ref_advance::tests::request(parents);
    request.commit.tree = root.root_identity();
    request.uploads = [child, root]
        .iter()
        .flat_map(|tree| tree.nodes())
        .map(|node| StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: node.encoded().to_vec(),
        })
        .collect();
    Ok(request)
}

fn expected_nodes(request: &CommitRequest) -> TestResult<BTreeMap<Digest, Vec<u8>>> {
    request
        .uploads
        .iter()
        .map(|upload| {
            let StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } = upload
            else {
                return Err("fixture contains only canonical Node uploads".into());
            };
            Ok((
                TERRANE_V1
                    .calculate(IdentityKind::Node, bytes)?
                    .terrane_v1_digest()?,
                bytes.clone(),
            ))
        })
        .collect()
}

async fn check_published(
    repository: &Native,
    head: &RefRecord,
    revision: u64,
    later: &[&str],
    expected: &BTreeMap<Digest, Vec<u8>>,
) -> TestResult<Digest> {
    let guard = repository.coordinator().guard();
    let verified = guard.verified_tree(head.commit).await?;
    let interpretation =
        guard.historical_evidence_semantics(&verified.evidence, HistoryObservation::default())?;
    assert_eq!(
        interpretation,
        Selection::Recorded(RecordedContext::new(revision, 3, later)?)
    );
    assert!(guard.original_commit(&head.commit).is_ok());
    for (digest, bytes) in expected {
        let identity = TERRANE_V1.from_digest(IdentityKind::Node, digest)?;
        assert_eq!(guard.store().get(&identity, None).await?, *bytes);
    }

    let occurrences = verified.evidence.occurrences(262144)?;
    let root = verified.evidence.tree(verified.evidence.root, 262144)?;
    let mut child = None;
    for (key, retained) in [(b"a".as_slice(), "forever"), (b"b".as_slice(), "gc")] {
        let entry = root.get(key).ok_or("missing actual graft")?;
        let EntryKind::Tree {
            root,
            props: Some(props),
        } = &entry.kind
        else {
            return Err("published Entry must retain the complete graft override".into());
        };
        assert!(child.is_none_or(|previous| previous == *root));
        child = Some(*root);
        for name in later {
            assert_eq!(
                props
                    .iter()
                    .find(|property| property.name == *name)
                    .map(|property| property.value),
                Some(b"\x00".as_slice())
            );
        }
        let path = [b"/".as_slice(), key].concat();
        let occurrence = occurrences
            .iter()
            .find(|occurrence| occurrence.path == path)
            .ok_or("missing graft occurrence")?;
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let policy = interpretation.resolve(&layers, guard.defaults_for(&verified.evidence))?;
        assert_eq!(
            policy.get(PropertyName::Retain),
            Some(&Value::Text(retained))
        );
        assert!(policy.active_index_roots().is_none());
        assert!(policy.get(PropertyName::IndexGaps).is_none());
    }
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(head.clone()));
    Ok(verified.evidence.root)
}

/// Checks inert graft overrides through native publication and historical rollback.
///
/// # Errors
/// Preserves fixture, admission, publication, verification, reopen and rollback failures.
///
/// # Panics
/// Panics when preservation or rollback invariant assertions fail.
pub(super) async fn preserves_inert_overrides_through_publication_and_rollback() -> TestResult {
    for (revision, later) in [(1, PRESERVED), (2, &PRESERVED[1..])] {
        let location = Location::open().await?;
        let repository = location
            .reopen(revision, later, vec![location.baseline_selection()?])
            .await?;
        let token = crate::ref_advance::tests::token();
        let mut session = repository.begin(REFERENCE, &token, "sdk").await?;
        let overrides = later
            .iter()
            .map(|name| Property {
                name,
                value: b"\x00",
            })
            .collect::<Vec<_>>();
        let candidate = request(vec![location.baseline.commit], &overrides, None)?;
        let expected = expected_nodes(&candidate)?;

        let first = repository.commit_request(&mut session, candidate).await?;
        let root = check_published(&repository, &first, revision, later, &expected).await?;
        let second = repository
            .commit_request(
                &mut session,
                crate::ref_advance::tests::request(vec![first.commit]),
            )
            .await?;
        let second_root = repository
            .coordinator()
            .guard()
            .verified_tree(second.commit)
            .await?
            .evidence
            .root;
        drop(session);
        drop(repository);

        // Reopening under newer authoring inputs must not reinterpret the older
        // immutable target restored by the real existing-view admission branch.
        let rows = vec![
            location.baseline_selection()?,
            selected(first.commit, root, revision, later)?,
            selected(second.commit, second_root, revision, later)?,
        ];
        let reopened = location.reopen(3, &[], rows).await?;
        let mut session = reopened.begin(REFERENCE, &token, "sdk").await?;
        let rolled_back = reopened
            .coordinator()
            .rollback(&mut session, first.commit, &token, "sdk")
            .await?;
        assert_eq!(rolled_back.commit, first.commit);
        assert_eq!(rolled_back.seq, second.seq + 1);
        check_published(&reopened, &rolled_back, revision, later, &expected).await?;
    }
    Ok(())
}

async fn files(root: &std::path::Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut pending = vec![root.to_owned()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = TokioLocalFs.symlink_metadata(&path).await?;
        if metadata.is_dir() {
            pending.extend(TokioLocalFs.read_dir(&path).await?);
        } else {
            assert!(
                metadata.is_file(),
                "native fixture must contain ordinary leaves"
            );
            result.insert(
                path.strip_prefix(root)?.to_owned(),
                TokioLocalFs.read_nofollow(&path).await?,
            );
        }
    }
    Ok(result)
}

fn noncanonical_override(request: &mut CommitRequest) -> TestResult {
    let original = request.commit.tree;
    for upload in &mut request.uploads {
        let StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        } = upload
        else {
            continue;
        };
        if TERRANE_V1
            .calculate(IdentityKind::Node, bytes)?
            .terrane_v1_digest()?
            != original
        {
            continue;
        }
        let marker = b"\x6bfuture-note\x00";
        let start = bytes
            .windows(marker.len())
            .position(|candidate| candidate == marker)
            .ok_or("missing literal preserved graft value")?;
        let position = start + marker.len() - 1;
        bytes.splice(position..=position, [0x18, 0x00]);
        request.commit.tree = TERRANE_V1
            .calculate(IdentityKind::Node, bytes)?
            .terrane_v1_digest()?;
        return Ok(());
    }
    Err("missing candidate root upload".into())
}

/// Checks native graft refusals without changing published data or selected inputs.
///
/// # Errors
/// Preserves fixture, admission, publication, verification, reopen and filesystem failures.
///
/// # Panics
/// Panics when unchanged-state or refusal invariant assertions fail.
pub(super) async fn refuses_untrusted_malformed_and_unauthorized_overrides_before_publication()
-> TestResult {
    for (case, revision, later, name, child_acl) in [
        ("untrusted", 1, &[][..], "future-note", None),
        ("active-owner", 2, &[][..], "index-roots", None),
        ("active-auxiliary", 3, &[][..], "index-gaps", None),
        ("malformed", 1, PRESERVED, "future-note", None),
        ("domain", 1, PRESERVED, "domain", None),
        (
            "inherited-admin",
            1,
            PRESERVED,
            "future-note",
            Some(WRITER_COMMIT),
        ),
        (
            "delegation-without-admin",
            1,
            PRESERVED,
            "future-note",
            Some(WIDER),
        ),
    ] {
        let location = Location::open().await?;
        let repository = location
            .reopen(revision, later, vec![location.baseline_selection()?])
            .await?;
        let mut session = repository
            .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
            .await?;

        // Publish a genuine positive control in the same route/profile/session.
        // It also establishes this writer's independently protected bootstrap.
        let positive = request(vec![location.baseline.commit], &[], None)?;
        let head = repository.commit_request(&mut session, positive).await?;
        let value = if case == "domain" {
            b"\x6cprivate:test".as_slice()
        } else {
            b"\x00"
        };
        let mut candidate = request(vec![head.commit], &[Property { name, value }], child_acl)?;
        if case == "malformed" {
            // Independent malformed wire bypasses the rejecting Tree builder;
            // the new digest still binds the actual changed full Node bytes.
            noncanonical_override(&mut candidate)?;
        }
        if case == "delegation-without-admin" {
            let authority = Token::decode(&candidate.token)?;
            candidate.token = authority
                .attenuate(
                    Attenuation {
                        grants: Some(vec![Grant::new(
                            "refs/**".to_owned(),
                            Verbs::new(Verb::Commit as u8)?,
                        )?]),
                        ..Attenuation::default()
                    },
                    &candidate.terminal_secret,
                    authority.signing_public_key(),
                )?
                .encode();
        }
        let guard = repository.coordinator().guard();
        let payload_before = files(&location.root).await?;
        let protected_before = files(&location.control).await?;
        let selection_before = guard.selected_view_inputs(
            head.commit,
            guard.verified_tree(head.commit).await?.evidence.root,
            HistoryObservation::default(),
        )?;

        assert!(
            repository
                .commit_request(&mut session, candidate)
                .await
                .is_err(),
            "{case}"
        );

        assert_eq!(
            guard.store().ref_get(REFERENCE).await?,
            Some(head.clone()),
            "{case} whole head"
        );
        assert_eq!(
            files(&location.root).await?,
            payload_before,
            "{case} immutable and mutable payload leaves"
        );
        assert_eq!(
            files(&location.control).await?,
            protected_before,
            "{case} protected associations"
        );
        assert_eq!(
            guard.selected_view_inputs(
                head.commit,
                guard.verified_tree(head.commit).await?.evidence.root,
                HistoryObservation::default()
            )?,
            selection_before,
            "{case} retained selection"
        );
    }
    Ok(())
}
