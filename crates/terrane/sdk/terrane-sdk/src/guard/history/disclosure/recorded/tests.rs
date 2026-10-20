//! Checks Recorded disclosure against genuinely published native certificates.
//!
//! Supported Legacy publication precedes independently configured historical
//! requalification. These fixtures retain the actual Original verifier and
//! native dispatcher; they never construct completed evidence or authority.

use std::{
    error::Error,
    path::{Path, PathBuf},
};

use crate::guard::admission::tests::support::{
    ObservedGuard, observed, observed_with_recorded_selections,
};
use crate::guard::consumed::view_interpretation::compare_selected_data;
use crate::guard::{ConsumedResolver, HistoryObservation, VerifiedCollectionTree};
use crate::ref_advance::disclosure_tests::{independent_factory, witness_support::proposal};
use crate::ref_advance::native_fixture::NativeFixture;
use crate::ref_advance::{DisclosureCommitRequest, DisclosureCommitSelection};
use crate::repository::local_authority::LocalAuthority;
use crate::repository::local_authority::retention::Record;
use crate::store::{ContentStore, InvalidReason, RefStore, StoreErrorKind, TokioLocalFs};
use terrane_format::{
    gc::publication::evidence::{LineageUsedInputs, ViewInterpretationMode},
    identity::{Digest, IdentityKind, TERRANE_V1},
    properties::semantics::{
        RecordedContext,
        associations::{RecordedAssociation, RecordedAssociations},
    },
    refs::{Commit, RefRecord},
    tree_builder::Tree,
    tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse},
};

mod stage;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const REFERENCE: &str = "refs/heads/_/main";
const MINIMUM: u64 = 262_144;
const PUBLIC_BYTES: &[u8] = b"ordinary public dependency must complete independently";
const DISCLOSED_BYTES: &[u8] = b"genuine independently interpreted historical certificate";
const UNUSED_VIEW: Digest = [0xa5; 32];
const UNUSED_ROOT: Digest = [0x5a; 32];

struct Published {
    destination: NativeFixture<TokioLocalFs>,
    authority: LocalAuthority,
    source: RefRecord,
    source_root: Digest,
    previous: RefRecord,
    previous_root: Digest,
    certified: RefRecord,
    certified_root: Digest,
}

fn file(key: &[u8], plaintext: &[u8]) -> TestResult<LeafItem<'static>> {
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
    Ok(LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::File {
                mode: 0o644,
                size: plaintext.len() as u64,
                content: ContentRef::Inline(identity.terrane_v1_digest()?),
                link_id: None,
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    })
}

fn properties(private: bool) -> Option<Vec<Property<'static>>> {
    Some(vec![
        Property {
            name: "acl",
            value: b"\x81\x82\x66writer\x18\x1f",
        },
        Property {
            name: "domain",
            value: if private {
                b"\x6eprivate:writer"
            } else {
                b"\x66public"
            },
        },
    ])
}

async fn stored_root(
    destination: &NativeFixture<TokioLocalFs>,
    head: &RefRecord,
) -> TestResult<Digest> {
    let identity = TERRANE_V1.from_digest(IdentityKind::Commit, &head.commit)?;
    let bytes = destination.store().get(&identity, None).await?;
    Ok(Commit::decode(&bytes)?.tree)
}

/// Publishes a certified cut with a separate genuinely retained public ancestor.
async fn published() -> TestResult<Published> {
    let (source, source_authority, _) = independent_factory("private:writer").await;
    let (destination, authority, _) = independent_factory("public").await;
    let private = Tree::build(
        vec![file(b"file", DISCLOSED_BYTES)?],
        properties(true),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    let prior = Tree::build(
        vec![file(b"base", PUBLIC_BYTES)?],
        properties(false),
        MINIMUM,
        TreeUse::Ordinary,
    )?;
    let public = Tree::build(
        vec![
            file(b"base", PUBLIC_BYTES)?,
            file(b"file", DISCLOSED_BYTES)?,
        ],
        properties(false),
        MINIMUM,
        TreeUse::Ordinary,
    )?;

    let mut source_writer = source
        .begin(REFERENCE, source_authority.token(), "sdk")
        .await
        .map_err(|error| stage::failure("source begin", error))?;
    let source_head = source
        .advance(
            &mut source_writer,
            proposal(&source_authority, Vec::new(), &private, &[DISCLOSED_BYTES]),
        )
        .await
        .map_err(|error| stage::failure("source advance", error))?;
    let mut writer = destination
        .begin(REFERENCE, authority.token(), "sdk")
        .await
        .map_err(|error| stage::failure("destination begin", error))?;
    let previous = destination
        .advance(
            &mut writer,
            proposal(&authority, Vec::new(), &prior, &[PUBLIC_BYTES]),
        )
        .await
        .map_err(|error| stage::failure("destination advance", error))?;
    let certified = destination
        .advance_disclosure(
            source.guard(),
            &mut writer,
            DisclosureCommitRequest {
                proposal: proposal(
                    &authority,
                    vec![previous.commit],
                    &public,
                    &[PUBLIC_BYTES, DISCLOSED_BYTES],
                ),
                selections: vec![DisclosureCommitSelection {
                    source_reference: REFERENCE.into(),
                    source_commit: source_head.commit,
                    source_path: b"/file".to_vec(),
                    source_token: source_authority.token().to_vec(),
                    destination_path: b"/file".to_vec(),
                }],
            },
        )
        .await
        .map_err(|error| stage::failure("destination disclosure advance", error))?;

    // Certificate admission adds signed metadata. Use the actual stored Commit
    // root, not the offered pre-certificate tree's identity.
    let source_root = stored_root(&source, &source_head)
        .await
        .map_err(|error| stage::failure("stored source root", error))?;
    let previous_root = stored_root(&destination, &previous)
        .await
        .map_err(|error| stage::failure("stored destination previous root", error))?;
    let certified_root = stored_root(&destination, &certified)
        .await
        .map_err(|error| stage::failure("stored certified destination root", error))?;
    assert_eq!(previous_root, prior.root_identity());

    Ok(Published {
        destination,
        authority,
        source: source_head,
        source_root,
        previous,
        previous_root,
        certified,
        certified_root,
    })
}

fn association(view: Digest, root: Digest, later: &[&str]) -> TestResult<RecordedAssociation> {
    Ok(RecordedAssociation::new(
        view,
        root,
        RecordedContext::new(3, 3, later)?,
    ))
}

fn install(fixture: &Published, rows: Vec<RecordedAssociation>) -> TestResult<ObservedGuard> {
    Ok(observed_with_recorded_selections(
        fixture.destination.guard(),
        RecordedAssociations::new(rows)?,
    ))
}

fn reader(fixture: &Published, later: &[&str], unused: bool) -> TestResult<ObservedGuard> {
    let mut rows = vec![
        association(fixture.previous.commit, fixture.previous_root, later)?,
        association(fixture.certified.commit, fixture.certified_root, later)?,
    ];
    if unused {
        rows.push(association(
            UNUSED_VIEW,
            UNUSED_ROOT,
            &["unrelated-preserved"],
        )?);
    }
    install(fixture, rows)
}

async fn complete(
    guard: &ObservedGuard,
    view: Digest,
) -> TestResult<(VerifiedCollectionTree, LineageUsedInputs)> {
    let authority = guard.configured_original_authority()?;
    let consumed = ConsumedResolver::new(guard, &authority)?;
    let checked = guard
        .verified_collection_tree_observed(view, HistoryObservation::default().tracked(&consumed))
        .await?;
    let inputs = consumed.finish()?;
    guard.store().assert_no_effects();
    Ok((checked, inputs))
}

fn association_path(guard: &ObservedGuard, view: Digest) -> TestResult<PathBuf> {
    let original = guard.original_commit(&view)?;
    let suffix = view
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(original
        .baseline()
        .authority()
        .control()
        .join(format!("commit-{suffix}.cbor")))
}

/// Restores only this isolated fixture's own canonical protected input bytes.
fn restore(path: &Path, bytes: &[u8]) -> TestResult {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[tokio::test]
async fn recorded_disclosure_completes_actual_history_and_context() -> TestResult {
    let fixture = published().await?;
    let guard = reader(&fixture, &["future-disclosure-name"], false)
        .map_err(|error| stage::failure("Recorded reader configuration", error))?;
    let (checked, inputs) = complete(&guard, fixture.certified.commit)
        .await
        .map_err(|error| stage::failure("Recorded certified collection completion", error))?;
    let completed = checked.completed();
    let dependencies = completed
        .dependencies(fixture.certified.commit)
        .ok_or("certified dependency row missing")?;
    let batch = dependencies.disclosure().ok_or("completed batch missing")?;

    assert_eq!(batch.view(), fixture.certified.commit);
    assert_eq!(dependencies.parents(), &[fixture.previous.commit]);
    assert_eq!(dependencies.witnesses(), &[fixture.previous.commit]);
    assert_eq!(batch.required_commits(), &[fixture.previous.commit]);
    assert!(batch.certified_parent(fixture.certified.commit, fixture.source.commit));
    assert!(completed.dependencies(fixture.previous.commit).is_some());
    assert!(completed.dependencies(fixture.source.commit).is_none());
    assert!(
        completed
            .history()
            .commit(&fixture.previous.commit)
            .is_some()
    );
    assert!(completed.history().commit(&fixture.source.commit).is_none());
    assert_eq!(batch.boundaries().len(), 1);
    assert_eq!(batch.boundaries()[0].root_occurrences(), &[b"/".to_vec()]);

    let contexts = inputs
        .view_interpretations
        .as_ref()
        .ok_or("context key7 missing")?;
    assert_eq!(contexts.len(), 2);
    for (view, root) in [
        (fixture.previous.commit, fixture.previous_root),
        (fixture.certified.commit, fixture.certified_root),
    ] {
        let context = contexts
            .iter()
            .find(|row| row.view == view)
            .ok_or("used view absent")?;
        assert_eq!(context.original_root, root);
        assert_eq!(context.mode, ViewInterpretationMode::Recorded);
        assert_eq!(context.registries.property_revision, 3);
        assert_eq!(context.registries.behavioral_properties.len(), 35);
        assert_eq!(
            context.registries.later_properties,
            ["future-disclosure-name"]
        );
        assert_eq!(context.registries.attribute_revision, 1);
        assert_eq!(context.registries.selector_revision, 1);
        assert_eq!(context.registries.tree_revision, 1);
        assert_eq!(context.registries.chunk_revision, 1);
        assert_eq!(context.registries.identity_profile, "terrane-v1");
    }
    assert!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, fixture.previous.commit)
            > 0
    );
    assert_eq!(
        guard
            .store()
            .content_reads(IdentityKind::Commit, fixture.source.commit),
        0
    );
    assert_eq!(
        guard
            .store()
            .content_reads(IdentityKind::Node, fixture.source_root),
        0
    );
    assert!(!inputs.controls.is_empty());
    assert!(!inputs.disclosures.is_empty());
    assert!(
        inputs
            .views
            .iter()
            .all(|row| row.view != fixture.source.commit)
    );

    let unrelated = reader(&fixture, &["future-disclosure-name"], true)?;
    let (_, unchanged) = complete(&unrelated, fixture.certified.commit).await?;
    assert_eq!(unchanged.view_interpretations, inputs.view_interpretations);
    assert_eq!(unchanged.views, inputs.views);
    assert_eq!(unchanged.controls, inputs.controls);
    assert!(unchanged.views.iter().all(|row| row.view != UNUSED_VIEW));
    assert_eq!(
        fixture.destination.store().ref_get(REFERENCE).await?,
        Some(fixture.certified.clone())
    );
    Ok(())
}

#[tokio::test]
async fn recorded_disclosure_refuses_missing_or_wrong_original_associations() -> TestResult {
    let fixture = published().await?;
    let prior = association(fixture.previous.commit, fixture.previous_root, &[])?;
    let target = association(fixture.certified.commit, fixture.certified_root, &[])?;
    let cases = [
        (
            "missing destination",
            vec![prior.clone()],
            StoreErrorKind::Unsupported,
            false,
        ),
        (
            "wrong destination original root",
            vec![
                prior,
                association(fixture.certified.commit, UNUSED_ROOT, &[])?,
            ],
            StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
            false,
        ),
        (
            "missing required ancestor",
            vec![target.clone()],
            StoreErrorKind::Unsupported,
            true,
        ),
        (
            "wrong required ancestor original root",
            vec![
                association(fixture.previous.commit, UNUSED_ROOT, &[])?,
                target,
            ],
            StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
            true,
        ),
    ];

    for (name, rows, expected, destination_prepared) in cases {
        let guard = install(&fixture, rows)?;
        let authority = guard.configured_original_authority()?;
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        let result = guard
            .verified_collection_tree_observed(
                fixture.certified.commit,
                HistoryObservation::default().tracked(&consumed),
            )
            .await;
        let failure = result.err().ok_or("invalid mapping completed")?;

        assert_eq!(failure.kind(), &expected, "{name}");
        assert!(
            consumed
                .observed_completed_view_contexts_for_tests()?
                .is_empty(),
            "{name}"
        );
        assert_eq!(
            consumed
                .candidate_preparation_pending(fixture.certified.commit)?
                .is_some(),
            destination_prepared,
            "{name}"
        );
        if destination_prepared {
            let unfinished = consumed
                .finish()
                .err()
                .ok_or("failed ancestor finalized destination preparation")?;
            assert_eq!(
                unfinished.kind(),
                &StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
                "{name}"
            );
        } else {
            let unprepared = consumed.finish()?;
            assert!(unprepared.views.is_empty(), "{name}");
            assert_eq!(unprepared.view_interpretations, Some(Vec::new()), "{name}");
        }
        guard.store().assert_no_effects();
    }
    let guard = reader(&fixture, &[], false)?;
    let (_, completed) = complete(&guard, fixture.certified.commit).await?;
    assert_eq!(completed.views.len(), 2);
    Ok(())
}

#[tokio::test]
async fn recorded_disclosure_requires_complete_dependencies_and_exact_current_fence() -> TestResult
{
    let fixture = published().await?;
    let guard = reader(&fixture, &["captured-later-name"], false)?;
    let (checked, inputs) = complete(&guard, fixture.certified.commit).await?;
    let context = inputs
        .view_interpretations
        .as_ref()
        .and_then(|rows| rows.iter().find(|row| row.view == fixture.certified.commit))
        .ok_or("successful context missing")?;
    let verified = checked
        .completed()
        .history()
        .commit(&fixture.certified.commit)
        .ok_or("successful signed commit missing")?;
    let selected = guard.select_view(
        verified.identity(),
        verified.commit().tree,
        HistoryObservation::default(),
    )?;
    compare_selected_data(Some(context), &selected, verified, &context.registries)?;
    let changed = reader(&fixture, &["different-later-name"], false)?;
    let changed_selected = changed.select_view(
        verified.identity(),
        verified.commit().tree,
        HistoryObservation::default(),
    )?;
    let profile =
        crate::guard::history::completion::profile_inputs(&changed, verified, &changed_selected)?;
    let mismatch = compare_selected_data(Some(context), &changed_selected, verified, &profile)
        .err()
        .ok_or("changed current fence reused captured data")?;
    assert_eq!(
        mismatch.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    let absent = compare_selected_data(None, &selected, verified, &context.registries)
        .err()
        .ok_or("absent context allowed reuse")?;
    assert_eq!(absent.kind(), &StoreErrorKind::Unsupported);

    // The ancestor is a noncertified dependency. Its real Original association
    // must complete independently, even when the private parent has a valid cut.
    for view in [fixture.previous.commit, fixture.certified.commit] {
        let path = association_path(&guard, view)?;
        let bytes = std::fs::read(&path)?;
        std::fs::remove_file(&path)?;
        let authority = guard.configured_original_authority()?;
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        let result = guard
            .verified_collection_tree_observed(
                fixture.certified.commit,
                HistoryObservation::default().tracked(&consumed),
            )
            .await;
        restore(&path, &bytes)?;

        let failure = result
            .err()
            .ok_or("missing actual Original dependency completed")?;
        assert_eq!(
            failure.kind(),
            &StoreErrorKind::Unavailable { retry_after: None },
        );
        assert_eq!(
            failure
                .source()
                .and_then(|source| source.downcast_ref::<std::io::Error>())
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotFound),
        );
        assert!(
            consumed
                .observed_completed_view_contexts_for_tests()?
                .is_empty()
        );
        let unfinished = consumed
            .finish()
            .err()
            .ok_or("failed Original dependency finalized pending views")?;
        assert_eq!(
            unfinished.kind(),
            &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
        );
        guard.store().assert_no_effects();
        let (_, restored) = complete(&guard, fixture.certified.commit).await?;
        assert_eq!(restored.views.len(), 2);
    }
    let (_, requalified) = complete(&changed, fixture.certified.commit).await?;
    assert_ne!(
        requalified.view_interpretations,
        inputs.view_interpretations
    );
    Ok(())
}

#[tokio::test]
async fn recorded_disclosure_keeps_original_roles_and_current_read_independent() -> TestResult {
    let fixture = published().await?;
    let guard = reader(&fixture, &[], false)?;
    let (checked, _) = complete(&guard, fixture.certified.commit).await?;
    let batch = checked
        .completed()
        .dependencies(fixture.certified.commit)
        .and_then(|row| row.disclosure())
        .ok_or("real checked batch absent")?;
    let boundary = batch
        .boundaries()
        .first()
        .ok_or("real signed boundary absent")?;
    let mut trust = guard
        .retained_public_trust()?
        .into_iter()
        .find(|row| {
            row.disclosure_roles.iter().any(|role| {
                role.repository == boundary.authority_repository()
                    && role.public_key == *boundary.authority_key()
                    && role.domain == boundary.authority_domain()
            })
        })
        .ok_or("factory-retained source role absent")?;
    let authority = guard.configured_original_authority()?;
    let path = authority.control().join(trust.selector()?);
    let bytes = std::fs::read(&path)?;
    trust.disclosure_roles.clear();
    std::fs::write(&path, trust.encode()?)?;
    let consumed = ConsumedResolver::new(&guard, &authority)?;
    let result = guard
        .verified_collection_tree_observed(
            fixture.certified.commit,
            HistoryObservation::default().tracked(&consumed),
        )
        .await;
    std::fs::write(&path, &bytes)?;

    let failure = result
        .err()
        .ok_or("changed retained source role completed")?;
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    let unfinished = consumed
        .finish()
        .err()
        .ok_or("changed retained role finalized pending views")?;
    assert_eq!(
        unfinished.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    complete(&guard, fixture.certified.commit).await?;

    let legacy = observed(fixture.destination.guard());
    let (_, legacy_inputs) = complete(&legacy, fixture.certified.commit).await?;
    assert!(
        legacy_inputs
            .view_interpretations
            .as_ref()
            .ok_or("legacy key7 absent")?
            .iter()
            .all(|row| row.mode == ViewInterpretationMode::Legacy)
    );

    let revoked_proposal = {
        let read = fixture
            .destination
            .guard()
            .read_snapshot(REFERENCE, fixture.authority.token(), b"/file", "sdk")
            .await?;
        let tree = read.evidence.tree(read.evidence.root, MINIMUM)?;
        let mut policy = tree
            .props()
            .ok_or("actual published root has no policy")?
            .to_vec();
        let acl = policy
            .iter_mut()
            .find(|row| row.name == "acl")
            .ok_or("actual root lacks acl")?;
        acl.value = b"\x81\x82\x66writer\x00";
        let revoked = tree.with_properties(Some(policy))?.tree;
        proposal(
            &fixture.authority,
            vec![fixture.certified.commit],
            &revoked,
            &[PUBLIC_BYTES, DISCLOSED_BYTES],
        )
    };
    let mut writer = fixture
        .destination
        .begin(REFERENCE, fixture.authority.token(), "sdk")
        .await?;
    let narrowed = fixture
        .destination
        .advance(&mut writer, revoked_proposal)
        .await?;
    let narrowed_root = stored_root(&fixture.destination, &narrowed).await?;
    let current = install(
        &fixture,
        vec![
            association(fixture.previous.commit, fixture.previous_root, &[])?,
            association(fixture.certified.commit, fixture.certified_root, &[])?,
            association(narrowed.commit, narrowed_root, &[])?,
        ],
    )?;
    let (_, historical) = complete(&current, fixture.certified.commit).await?;
    assert_eq!(historical.views.len(), 2);
    let denied = current
        .read_snapshot(REFERENCE, fixture.authority.token(), b"/file", "sdk")
        .await
        .err()
        .ok_or("historical certificate granted current Read")?;
    assert!(matches!(
        denied.kind(),
        StoreErrorKind::Denied { verb: "read", .. }
    ));
    assert!(denied.source().is_none());
    assert_eq!(
        fixture.destination.store().ref_get(REFERENCE).await?,
        Some(narrowed)
    );
    current.store().assert_no_effects();
    Ok(())
}

#[path = "tests/snapshot_projection_tests.rs"]
mod snapshot_projection_tests;
