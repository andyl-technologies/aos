//! Checks recorded contexts, public file reads and crate-private repository view projection.
//!
//! Genuine native publication and protected Original histories supply authority.

use super::*;
use crate::store::{LocalFs, TokioLocalFs};
use std::error::Error as _;
use terrane_format::provenance::{Preset, Selector, TrustContext, VerifiedHistory};
use terrane_format::surface::{View, ViewTarget};
use terrane_format::tree_format::{ContentRef, EntryKind};

const PLAINTEXT: &[u8] = b"recorded repository read callers";

fn views(commit: Digest) -> Result<[View; 2]> {
    Ok([
        View::parse(REFERENCE)?,
        View {
            target: ViewTarget::Commit(commit),
            subtree: Vec::new(),
            policy: None,
        },
    ])
}

async fn check_repository_reads(repository: &Native, commit: Digest) -> Result {
    let content = TERRANE_V1
        .calculate(IdentityKind::Chunk, PLAINTEXT)?
        .terrane_v1_digest()?;

    for view in views(commit)? {
        let (selected, bytes) = repository
            .read_file(&view, b"file", &token(), "sdk")
            .await?;
        assert_eq!(selected, commit);
        assert_eq!(bytes, PLAINTEXT);

        let projected = repository.read_view(&view, &token(), "sdk").await?;
        assert_eq!(projected.commit, commit);
        assert_eq!(projected.minimum, 262144);
        assert_eq!(projected.entries.len(), 1);
        let entry = &projected.entries[0];
        assert_eq!(entry.key, b"file");
        assert_eq!(entry.plaintext.as_deref(), Some(PLAINTEXT));
        let decoded =
            terrane_format::tree_format::decode_entry_bytes(&entry.encoded, projected.minimum)?;
        assert_eq!(
            decoded.kind,
            EntryKind::File {
                mode: 0o644,
                size: u64::try_from(PLAINTEXT.len())?,
                content: ContentRef::Inline(content),
                link_id: None,
            }
        );
        assert_eq!(decoded.attrs.len(), 1);
        assert_eq!(decoded.attrs[0].name, "note");
        assert_eq!(decoded.attrs[0].value, b"\x61x");
    }
    Ok(())
}

async fn check_repository_read_refusals(
    repository: &Native,
    commit: Digest,
    case: &str,
    expected: StoreErrorKind,
    io_source: Option<std::io::ErrorKind>,
) -> Result {
    for view in views(commit)? {
        let file_error = repository
            .read_file(&view, b"file", &token(), "sdk")
            .await
            .err()
            .ok_or_else(|| format!("{case}: read_file accepted {:?}", view.target))?;
        let view_error = repository
            .read_view(&view, &token(), "sdk")
            .await
            .err()
            .ok_or_else(|| format!("{case}: read_view accepted {:?}", view.target))?;

        for error in [file_error, view_error] {
            let crate::repository::Error::Store(failure) = error else {
                return Err(format!("{case}: lost typed Guard refusal: {error:?}").into());
            };
            if failure.kind() != &expected {
                return Err(format!("{case}: unexpected Guard refusal: {failure:?}").into());
            }
            if let Some(expected_source) = io_source {
                let source = failure
                    .source()
                    .and_then(|source| source.downcast_ref::<std::io::Error>())
                    .ok_or_else(|| format!("{case}: protected-file I/O cause was lost"))?;
                if source.kind() != expected_source {
                    return Err(
                        format!("{case}: unexpected protected-file I/O cause: {source:?}").into(),
                    );
                }
            }
        }
    }
    Ok(())
}

// This model uses primitive CBOR fields, independent of the evaluator encoder.
fn expected_context(view: Digest, root: Digest, revision: u64, later: &[&str]) -> Vec<u8> {
    use terrane_format::cbor;

    let mut names = LEGACY_NAMES.to_vec();
    if revision >= 2 {
        names.push("index-roots");
    }
    if revision >= 3 {
        names.push("index-gaps");
    }
    names.sort();
    let mut later = later.to_vec();
    later.sort();
    let mut output = Vec::new();
    cbor::write_array(&mut output, 8);
    cbor::write_uint(&mut output, 3);
    cbor::write_bytes(&mut output, &view);
    cbor::write_text(&mut output, "public");
    cbor::write_bytes(&mut output, b"\x82\x66preset\x63any");
    output.push(0xf6);
    cbor::write_uint(&mut output, 262144);
    output.push(0xf6);
    cbor::write_array(&mut output, 4);
    cbor::write_bytes(&mut output, &root);
    cbor::write_uint(&mut output, revision);
    cbor::write_array(&mut output, names.len());
    for name in names {
        cbor::write_text(&mut output, name);
    }
    cbor::write_array(&mut output, later.len());
    for name in later {
        cbor::write_text(&mut output, name);
    }
    output
}

#[tokio::test]
async fn selected_read_configuration_constructs_checked_recorded_evaluators() -> Result {
    let legacy = crate::guard::recorded_native_fixture::fixture(false).await?;
    let mut session = legacy.begin(REFERENCE, &token(), "sdk").await?;
    let first = legacy
        .commit_request(
            &mut session,
            crate::ref_advance::tests::request_file(Vec::new(), PLAINTEXT),
        )
        .await?;
    let root = signed_root(&legacy, first.commit).await?;
    let legacy_history = legacy
        .coordinator()
        .guard()
        .verified_history(first.commit)
        .await?;
    let legacy_evaluator = TrustContext::new(
        &legacy_history,
        first.commit,
        Selector::preset(Preset::Any),
        "public",
        None,
    )?;
    let legacy_context = legacy_evaluator.canonical_context().to_vec();
    let location = Location::capture(&legacy, first.commit).await?;
    drop(legacy_evaluator);
    drop(legacy_history);
    drop(session);
    drop(legacy);

    let mut contexts = Vec::new();
    for (revision, later) in [
        (1, vec!["index-gaps", "index-roots"]),
        (2, vec!["index-gaps"]),
        (3, Vec::new()),
    ] {
        let repository = location
            .reopen(
                3,
                2,
                &[],
                vec![selected(first.commit, root, revision, 1, &later)?],
            )
            .await?;
        let history = repository
            .coordinator()
            .guard()
            .verified_history(first.commit)
            .await?;
        let trust = TrustContext::new(
            &history,
            first.commit,
            Selector::preset(Preset::Any),
            "public",
            None,
        )?;
        // The immutable signed namespace supplies the root; the caller has no root override.
        assert_eq!(trust.view_root(), root);
        assert_eq!(
            trust.canonical_context(),
            expected_context(first.commit, root, revision, &later)
        );
        terrane_format::provenance::validate_canonical_context(trust.canonical_context())?;
        contexts.push(trust.canonical_context().to_vec());
        assert!(
            TrustContext::new(
                &history,
                [9; 32],
                Selector::preset(Preset::Any),
                "public",
                None
            )
            .is_err()
        );
        assert!(
            TrustContext::new(
                &VerifiedHistory::new(262144),
                first.commit,
                Selector::preset(Preset::Any),
                "public",
                None
            )
            .is_err()
        );
        assert_contexts(
            &completed(&repository, first.commit).await?,
            &[Expected::recorded(first.commit, root, revision, 1, &later)],
        )?;
        drop(trust);
        drop(history);

        // Both repository callers must select the same checked interpretation
        // for ref and immutable views, then independently authorize content.
        let before = lineage(&repository).await?;
        check_repository_reads(&repository, first.commit).await?;
        assert_eq!(lineage(&repository).await?, before);
        drop(repository);

        assert_ne!(root, [9; 32]);
        let false_root = location
            .reopen(
                3,
                2,
                &[],
                vec![selected(first.commit, [9; 32], revision, 1, &later)?],
            )
            .await?;
        let failure = false_root
            .coordinator()
            .guard()
            .verified_history(first.commit)
            .await
            .err()
            .ok_or("caller root substitution overrode genuine signed history")?;
        assert!(matches!(
            failure.kind(),
            StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest)
        ));
        check_repository_read_refusals(
            &false_root,
            first.commit,
            "wrong selected root",
            StoreErrorKind::Invalid(crate::store::InvalidReason::MalformedRequest),
            None,
        )
        .await?;
    }
    assert_eq!(contexts.len(), 3);
    assert_ne!(contexts[0], contexts[1]);
    assert_ne!(contexts[1], contexts[2]);
    assert_ne!(legacy_context, contexts[2]);

    let missing = location.reopen(3, 2, &[], Vec::new()).await?;
    check_repository_read_refusals(
        &missing,
        first.commit,
        "missing selected view",
        StoreErrorKind::Unsupported,
        None,
    )
    .await?;
    drop(missing);

    let repository = location
        .reopen(3, 2, &[], vec![selected(first.commit, root, 3, 1, &[])?])
        .await?;
    let before = lineage(&repository).await?;
    let original = location.association(first.commit);
    let saved = original.with_extension("held");
    TokioLocalFs.rename(&original, &saved).await?;

    // Protected-file metadata failure must retain its actual missing-file cause.
    let refusal = check_repository_read_refusals(
        &repository,
        first.commit,
        "missing Original",
        StoreErrorKind::Unavailable { retry_after: None },
        Some(std::io::ErrorKind::NotFound),
    )
    .await;
    TokioLocalFs.rename(&saved, &original).await?;
    refusal?;
    check_repository_reads(&repository, first.commit).await?;
    assert_eq!(lineage(&repository).await?, before);

    // Zero grants revoke Read; Commit alone would still imply Read. The prior
    // root grants Admin, allowing this ordinary publication to revoke access.
    // Both complete Original histories remain valid without granting access.
    let mut session = repository.begin(REFERENCE, &token(), "sdk").await?;
    let current = repository
        .commit_request(
            &mut session,
            crate::ref_advance::tests::request_file_acl(
                vec![first.commit],
                b"current read revoked",
                0,
            ),
        )
        .await?;
    repository
        .coordinator()
        .guard()
        .verified_history(first.commit)
        .await?;
    repository
        .coordinator()
        .guard()
        .verified_history(current.commit)
        .await?;
    let before = lineage(&repository).await?;
    check_repository_read_refusals(
        &repository,
        first.commit,
        "current ACL denies Read",
        StoreErrorKind::Denied {
            verb: "read",
            pattern: REFERENCE.into(),
        },
        None,
    )
    .await?;
    assert_eq!(lineage(&repository).await?, before);
    assert_eq!(
        repository.coordinator().store().ref_get(REFERENCE).await?,
        Some(current)
    );
    Ok(())
}
