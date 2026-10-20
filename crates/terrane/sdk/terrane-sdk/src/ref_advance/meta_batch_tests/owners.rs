//! Exercises the private closed existing-owner carrier through real batch effects.
//!
//! Source history and authoring semantics are independently installed and checked.
//! Pair reads come only from ExistingOwnerReferences' native factory; their test
//! copies are observations, never replacements for the actual moved carrier.

use super::fs::Phase;
use super::support::{Fixture, Snapshot, TestResult, node, rejected, replace, required};
use super::{still_excluded, store_failure, wait};
use crate::bucket::publication::receipts::RecordRead;
use crate::guard::{ExistingOwnerReferences, SelectedReadInterpretation};
use crate::pack::PackReader;
use crate::ref_advance::{CommitRequest, StagedUpload, WriterSession};
use crate::repository::PreparedTree;
use crate::store::{ContentStore, LocalFs, RefStore, StoreErrorKind, TokioClock};
use std::error::Error;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_format::refs::RefRecord;
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Attribute, TreeUse};

const BODY: &[u8] = b"genuine retained owner payload";

/// Owns the actual ordinary proposal and the factory-produced source carrier.
struct OwnerPublication {
    /// The current real writer session returned by Repository::begin.
    session: WriterSession,
    /// Canonical metadata-only tree bytes owned outside all tree/arena borrows.
    tree: PreparedTree,
    /// Ordinary unsigned metadata and credentials for the same actual source.
    request: CommitRequest,
    /// Genuine native membership, source/history and original placement carrier.
    references: ExistingOwnerReferences,
    /// Independently built exact newly offered metadata members.
    members: Vec<(Identity, Vec<u8>)>,
    /// Read-only copies of the actual native factory's original artifact reads.
    reads: Vec<RecordRead>,
    /// The independently verified selected source and catalog observation.
    before: Snapshot,
    /// The exact actual source authority record.
    previous: RefRecord,
    /// The real unchanged payload whose placement must remain identical.
    payload: Identity,
}

/// Prepares a genuine unchanged-file metadata edit under explicit authoring inputs.
///
/// # Errors
/// Preserves actual source/history/current, Original, profile, native placement,
/// canonical tree and current writer-session failures.
///
/// # Panics
/// Panics for an unexpected configured profile, file shape, source scope or pair.
async fn prepare(fixture: &Fixture<TokioClock>) -> TestResult<OwnerPublication> {
    let guard = fixture.repository.coordinator().guard();
    let inputs = required(fixture.authoring.as_ref().ok_or("retained active inputs"));
    let token = crate::ref_advance::tests::token();
    let source = guard
        .read_snapshot("refs/heads/_/main", &token, b"/", "sdk")
        .await?;
    // The authorized source supplies the actual independently selected mode.
    // The native carrier factory below separately rechecks its whole profile.
    match &source.interpretation {
        SelectedReadInterpretation::Recorded(association) => {
            assert_eq!(association.view(), source.commit.identity());
            assert_eq!(association.original_root(), source.commit.commit().tree);
            assert_eq!(
                association.revision(),
                inputs.registries().property_revision
            );
        }
        SelectedReadInterpretation::Legacy => panic!("active owner source remained Legacy"),
    }
    assert_eq!(inputs.registries().property_revision, 3);
    assert_eq!(inputs.registries().attribute_revision, 2);
    let previous = required(
        fixture
            .bucket()
            .ref_get("refs/heads/_/main")
            .await?
            .ok_or("actual selected source"),
    );
    assert_eq!(source.commit.identity(), previous.commit);
    let before = fixture.snapshot().await?;
    let guard_path = required(before.guard.as_ref().ok_or("actual installed active Guard"));
    let selected_guard_bytes = fixture.fs.read_nofollow(guard_path).await?;
    let selected_guard =
        terrane_format::gc::publication::evidence::GuardSnapshot::decode(&selected_guard_bytes)?;
    // This is an independent output oracle, never a configuration input.
    assert_eq!(&selected_guard.registries, inputs.registries());

    let mut tree = {
        let old = source.evidence.tree(source.evidence.root, 262144)?;
        let mut items = old.iter().cloned().collect::<Vec<_>>();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key, b"file");
        let note = required(
            items[0]
                .entry
                .attrs
                .iter_mut()
                .find(|attribute| attribute.name == "note")
                .ok_or("genuine existing note"),
        );
        *note = Attribute {
            name: "note",
            value: b"\x61y",
        };
        let rebuilt = Tree::build(
            items,
            old.props().map(<[_]>::to_vec),
            262144,
            TreeUse::Ordinary,
        )?;
        PreparedTree::from_tree(&rebuilt)?
    };
    let mut members = Vec::new();
    for upload in &tree.uploads {
        match upload {
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } => members.push((
                TERRANE_V1.calculate(IdentityKind::Node, bytes)?,
                bytes.clone(),
            )),
            other => panic!("unexpected owned canonical tree upload: {other:?}"),
        }
    }
    assert_eq!(members.len(), 1);
    assert_eq!(tree.root(), members[0].0.terrane_v1_digest()?);
    assert_ne!(tree.root(), source.evidence.root);
    let mut request = crate::ref_advance::tests::request(vec![previous.commit]);
    request.commit.tree = tree.root();
    request.uploads.clear();
    for verbs in [14, 13] {
        let extra = node(verbs)?;
        request.uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: extra.1.clone(),
        });
        members.push(extra);
    }

    let references = guard
        .existing_owner_references(source, &mut tree, &request.uploads)
        .await?;
    let reads = references.reads().cloned().collect::<Vec<_>>();
    let payload = TERRANE_V1.calculate(IdentityKind::Chunk, BODY)?;
    let row = required(
        before
            .rows
            .get(&payload.terrane_v1_digest()?)
            .ok_or("actual selected payload placement"),
    );
    let paths = [
        fixture.bucket().root().join(row.pack().pack_key()),
        fixture.bucket().root().join(row.pack().index_key()),
    ];
    assert_eq!(
        reads.len(),
        paths.len(),
        "one real raw Chunk supplies exactly its pair"
    );
    for (read, path) in reads.iter().zip(&paths) {
        assert_eq!(read.path(), path.as_path());
    }
    let inventory = required(
        before
            .manifest
            .as_ref()
            .and_then(|manifest| manifest.inventory.as_ref())
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.pack_id == *row.pack().as_bytes())
            })
            .ok_or("independent old pair inventory"),
    );
    let pack = required(reads[0].bytes().ok_or("actual old pack bytes"));
    let index = required(reads[1].bytes().ok_or("actual old detached index bytes"));
    assert_eq!(pack.len() as u64, inventory.pack_size);
    assert_eq!(index.len() as u64, inventory.index_size);
    TERRANE_V1.verify(
        &TERRANE_V1.from_digest(IdentityKind::Pack, &inventory.pack_hash)?,
        pack,
    )?;
    TERRANE_V1.verify(
        &TERRANE_V1.from_digest(IdentityKind::Index, &inventory.index_hash)?,
        index,
    )?;
    PackReader::open(pack)?.check_index_object(index)?;
    let owner = fixture.fs.symlink_metadata(&fixture.original).await?.uid();
    for read in &reads {
        let metadata = required(read.metadata().ok_or("actual pair metadata"));
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), owner);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o022, 0);
        assert!(read.bytes().is_some_and(|bytes| !bytes.is_empty()));
    }
    let session = fixture
        .repository
        .begin("refs/heads/_/main", &token, "sdk")
        .await?;
    assert_eq!(session.record(), Some(&previous));
    Ok(OwnerPublication {
        session,
        tree,
        request,
        references,
        members,
        reads,
        before,
        previous,
        payload,
    })
}

/// Executes actual signed native publication with the original closed carrier.
///
/// # Errors
/// Preserves real admission, source/profile/current/Original and native ACK errors.
async fn publish(
    fixture: &Fixture<TokioClock>,
    proposal: OwnerPublication,
) -> Result<crate::repository::CommitReport, crate::repository::Error> {
    let OwnerPublication {
        mut session,
        tree,
        request,
        references,
        ..
    } = proposal;
    fixture
        .repository
        .commit_with_existing_owner_report(&mut session, tree, request, references)
        .await
}

/// Builds actual signed source history and payload before metadata-only observation.
///
/// # Errors
/// Preserves genuine active-profile initialization, content and publication failures.
///
/// # Panics
/// Propagates the shared canonical file proposal's setup assertions.
async fn fixture() -> TestResult<Fixture<TokioClock>> {
    let fixture = Fixture::active_owner().await?;
    fixture
        .publish(crate::ref_advance::tests::request_file(Vec::new(), BODY))
        .await?;
    fixture.fs.reset();
    Ok(fixture)
}

/// Proves genuine owner reads survive successful signed batched publication.
///
/// # Errors
/// Preserves actual factory/preparation/native publication and independent oracle failures.
///
/// # Panics
/// Panics when actual pair bytes, selected rows, creators, current history or ACK differ.
pub(super) async fn positive_owner_publication() -> TestResult {
    let fixture = fixture().await?;
    let proposal = prepare(&fixture).await?;
    let before = proposal.before.clone();
    let previous = proposal.previous.clone();
    let payload = proposal.payload.clone();
    let reads = proposal.reads.clone();
    let members = proposal.members.clone();
    let metadata = fixture.bucket().observe_content_for_tests();
    fixture.fs.reset();
    metadata.reset();

    let report = publish(&fixture, proposal).await?;

    assert_eq!(metadata.snapshot().chunk_gets, 0);
    let commit_identity = TERRANE_V1.from_digest(IdentityKind::Commit, &report.record.commit)?;
    let commit_bytes = fixture.bucket().get(&commit_identity, None).await?;
    let mut packed_members = members.clone();
    packed_members.push((commit_identity, commit_bytes.clone()));
    fixture.assert_pair(&packed_members).await?;
    assert!(fixture.validator.calls(IdentityKind::Commit, &commit_bytes) >= 1);
    let selected = fixture
        .assert_final_mutation(&members[0].0, Some(&previous), &before.backend)
        .await?;
    assert_eq!(selected, report.record);
    let after = fixture.snapshot().await?;
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.burn_owners, before.state.burn_owners);
    let old_manifest = required(before.manifest.as_ref().ok_or("actual old manifest"));
    let new_manifest = required(after.manifest.as_ref().ok_or("actual successor manifest"));
    assert_eq!(new_manifest.exclusions, old_manifest.exclusions);
    assert_eq!(new_manifest.burns, old_manifest.burns);
    for entry in required(
        old_manifest
            .inventory
            .as_ref()
            .ok_or("old complete inventory"),
    ) {
        assert!(
            required(
                new_manifest
                    .inventory
                    .as_ref()
                    .ok_or("new complete inventory")
            )
            .contains(entry)
        );
    }
    for (digest, row) in &before.rows {
        assert_eq!(after.rows.get(digest), Some(row));
    }
    assert_eq!(
        after.rows.get(&payload.terrane_v1_digest()?),
        before.rows.get(&payload.terrane_v1_digest()?)
    );
    for read in &reads {
        assert_eq!(
            fixture.fs.read_nofollow(read.path()).await?.as_slice(),
            required(read.bytes().ok_or("retained bytes"))
        );
        let old = required(read.metadata().ok_or("retained metadata"));
        let actual = fixture.fs.symlink_metadata(read.path()).await?;
        assert_eq!((actual.dev(), actual.ino()), (old.dev(), old.ino()));
    }
    let observations = fixture.fs.observations();
    assert_eq!(observations.raw.len(), 1);
    assert_eq!(observations.pending.len(), 2);
    assert_eq!(observations.committed.len(), 2);
    let history = fixture
        .repository
        .coordinator()
        .guard()
        .verified_history(report.record.commit)
        .await?;
    let committed = required(
        history
            .commit(&report.record.commit)
            .ok_or("real new signed history"),
    );
    assert_eq!(committed.commit().parents, vec![previous.commit]);
    assert_eq!(committed.commit().tree, members[0].0.terrane_v1_digest()?);
    Ok(())
}

/// Refuses changed genuine old pack/index reads at real early/Raw/final effects.
///
/// # Errors
/// Preserves real initialization, metadata-only factory, handoff and oracle failures.
///
/// # Panics
/// Panics if either old artifact is omitted from retention, a post-change sync runs,
/// a native acknowledgment succeeds, or an indeterminate slot is treated as rollback.
pub(super) async fn retained_owner_reads() -> TestResult {
    for phase in [Phase::Pending, Phase::Raw, Phase::Mutation] {
        for pair_member in [0, 1] {
            let fixture = Arc::new(fixture().await?);
            let proposal = prepare(&fixture).await?;
            let target = proposal.reads[pair_member].path().to_owned();
            let before = proposal.before.clone();
            let previous = proposal.previous.clone();
            let members = proposal.members.clone();
            fixture.fs.reset();
            let (arrived, release, after) = fixture.fs.pause(phase);
            let running = fixture.clone();
            let task = tokio::spawn(async move { publish(&running, proposal).await });
            wait(arrived).await?;
            let namespace_lock = fixture
                .bucket()
                .root()
                .join(terrane_format::bucket::BucketKey::parse("CAPABILITIES")?.lock_name());
            let original_lock = fixture.original.join("retention.lock");
            still_excluded(&[namespace_lock, original_lock])?;
            replace(&target)?;
            required(release.send(()));

            let error = rejected(task.await?);

            let failure = store_failure(&error);
            assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
            let cause = required(failure.source().ok_or("actual retained pair failure"));
            assert!(matches!(
                cause.to_string().as_str(),
                "exact read metadata changed"
                    | "physical preimage changed"
                    | "exact read pathname changed"
                    | "current physical fence changed"
            ));
            assert!(
                after.try_recv().is_err(),
                "sync followed a changed retained pair pathname"
            );
            assert_eq!(fixture.fs.observations().reached, vec![phase]);
            if phase == Phase::Mutation {
                let installed = fixture
                    .assert_final_mutation(&members[0].0, Some(&previous), &before.backend)
                    .await?;
                match &error {
                    crate::repository::Error::Advance(
                        crate::ref_advance::AdvanceError::Indeterminate { observed, .. },
                    ) => {
                        assert_eq!(required(observed.as_ref()).as_deref(), Some(&installed));
                    }
                    other => {
                        panic!("expected post-slot native indeterminate pair refusal: {other:?}")
                    }
                }
            } else {
                assert_eq!(
                    fixture.bucket().ref_get("refs/heads/_/main").await?,
                    Some(previous)
                );
                let actual = fixture.snapshot().await?;
                assert_eq!(actual.state.branches, before.state.branches);
                assert_eq!(actual.state.sources, before.state.sources);
                assert_eq!(actual.state.guard, before.state.guard);
                assert_eq!(actual.state.loss_generation, before.state.loss_generation);
            }
        }
    }
    Ok(())
}
