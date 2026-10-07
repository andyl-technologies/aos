//! Exercises native metadata runs through ordinary signed repository publication.
//!
//! These finite witnesses use real native Original controls, ordinary schema and
//! identity validators, secure creators and closed executor-filled acknowledgments.
//! They establish no paired/backfill producer coverage or DRV-29 timing bound.

mod fs;
mod support;

use crate::{
    ref_advance::{AdvanceError, StagedUpload},
    repository::Error as RepositoryError,
    store::{
        Clock, ContentStore, ContentUpload, CorruptSubject, EffectFault, InvalidReason, LocalFs,
        MetaUpload, RefStore, StoreErrorKind, StoreFailure, TokioLocalFs,
    },
};
use fs::{Action, Phase};
use std::{error::Error, sync::Arc, time::Duration};
use support::{Fixture, TestResult, expiry_clock, node, put, rejected, replace, request, required};
use terrane_core::{
    bucket::BucketKey,
    derivation::Memo,
    identity::{IdentityKind, TERRANE_V1},
    indexing::IndexEvaluationRecipe,
    refs::Commit,
};

fn store_failure(error: &RepositoryError) -> &StoreFailure {
    match error {
        RepositoryError::Store(failure)
        | RepositoryError::Advance(AdvanceError::Store(failure)) => failure,
        RepositoryError::Advance(AdvanceError::Indeterminate { source, .. }) => source,
        other => panic!("expected original native Store failure, got {other:?}"),
    }
}

fn acknowledgment_failure(error: &RepositoryError, message: &str) {
    let failure = store_failure(error);
    assert!(matches!(failure.kind(), StoreErrorKind::Unsupported));
    let source = required(failure.source().ok_or("preserved native ACK source"));
    assert_eq!(source.to_string(), message);
}

fn upload_failure(error: &RepositoryError) {
    assert_eq!(
        store_failure(error).kind(),
        &StoreErrorKind::Invalid(InvalidReason::Upload {
            rule_id: "STORE-33"
        })
    );
}

async fn wait(receiver: std::sync::mpsc::Receiver<()>) -> TestResult {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(10))).await??;
    Ok(())
}

fn still_excluded(paths: &[std::path::PathBuf]) -> TestResult {
    for path in paths {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        assert!(
            matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "real retained exclusion released at {}",
            path.display()
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_meta_batch_selects_one_genuine_pair_for_distinct_validated_members() -> TestResult {
    let fixture = Fixture::new().await?;
    let (proposal, members) = request(Vec::new(), &[30, 29])?;
    let backend = fixture.snapshot().await?.backend;

    let record = fixture.publish(proposal).await?;

    fixture.assert_pair(&members).await?;
    let observations = fixture.fs.observations();
    // The member run and the signed Commit each have their own ordinary pair;
    // the candidate's final CheckedMutation is a different selected boundary.
    assert_eq!(observations.raw.len(), 2);
    assert_eq!(observations.pending.len(), 4);
    assert_eq!(observations.committed.len(), 4);
    let selected = fixture
        .assert_final_mutation(&members[0].0, None, &backend)
        .await?;
    assert_eq!(selected, record);
    assert_eq!(
        fixture.bucket().ref_get("refs/heads/_/main").await?,
        Some(record.clone())
    );
    let history = fixture
        .repository
        .coordinator()
        .guard()
        .verified_history(record.commit)
        .await?;
    assert!(history.commit(&record.commit).is_some());
    for (identity, bytes) in members {
        assert!(fixture.validator.calls(identity.kind(), &bytes) >= 1);
    }

    // Real Chunk barriers retain the original offer order and make each inline
    // dependency durable before the corresponding Meta run validates it.
    let fixture = Fixture::new().await?;
    let (mut proposal, root) = request(Vec::new(), &[])?;
    let mut groups = Vec::new();
    for bytes in [
        b"first dependent chunk".as_slice(),
        b"second dependent chunk".as_slice(),
    ] {
        let file = crate::ref_advance::tests::request_file(Vec::new(), bytes);
        let mut node = None;
        let mut chunk = None;
        for upload in file.uploads {
            match upload {
                StagedUpload::Meta {
                    kind: IdentityKind::Node,
                    bytes,
                } => node = Some(bytes),
                upload @ StagedUpload::Chunk { .. } => chunk = Some(upload),
                other => panic!("unexpected genuine file upload: {other:?}"),
            }
        }
        groups.push((
            required(chunk.ok_or("actual dependent Chunk")),
            required(node.ok_or("actual file Node")),
        ));
    }
    let (first_chunk, first_node) = groups.remove(0);
    let (second_chunk, second_node) = groups.remove(0);
    let first_identity = TERRANE_V1.calculate(IdentityKind::Node, &first_node)?;
    let second_identity = TERRANE_V1.calculate(IdentityKind::Node, &second_node)?;
    let root_upload = required(proposal.uploads.pop().ok_or("ordinary empty root upload"));
    proposal.uploads = vec![
        first_chunk,
        root_upload,
        StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: first_node.clone(),
        },
        second_chunk,
        StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: second_node.clone(),
        },
    ];
    fixture.publish(proposal).await?;
    let selected = fixture.snapshot().await?;
    let root_row = required(
        selected
            .rows
            .get(&root[0].0.terrane_v1_digest()?)
            .ok_or("selected root"),
    );
    let first_row = required(
        selected
            .rows
            .get(&first_identity.terrane_v1_digest()?)
            .ok_or("first dependent Node"),
    );
    let second_row = required(
        selected
            .rows
            .get(&second_identity.terrane_v1_digest()?)
            .ok_or("second dependent Node"),
    );
    assert_eq!(root_row.pack(), first_row.pack());
    assert_ne!(root_row.pack(), second_row.pack());
    assert_eq!(
        fixture.bucket().get(&first_identity, None).await?,
        first_node
    );
    assert_eq!(
        fixture.bucket().get(&second_identity, None).await?,
        second_node
    );
    assert_eq!(fixture.fs.observations().raw.len(), 5);
    Ok(())
}

#[tokio::test]
async fn native_meta_batch_validates_duplicates_and_preserves_existing_and_empty_runs() -> TestResult
{
    let fixture = Fixture::new().await?;
    let (first, members) = request(Vec::new(), &[])?;
    let first = fixture.publish(first).await?;
    let old_commit_id = TERRANE_V1.from_digest(IdentityKind::Commit, &first.commit)?;
    let old_commit = fixture.bucket().get(&old_commit_id, None).await?;
    let signed_owner = Commit::decode(&old_commit)?;
    assert_eq!(signed_owner.tree, members[0].0.terrane_v1_digest()?);

    // The existing signed owner supplies immutable recipe inputs. This Memo is
    // only advisory metadata: storing/reoffering it proves no replay, coverage,
    // completed index or publication authority.
    let recipe = IndexEvaluationRecipe::new(signed_owner.tree, "uid")?;
    let memo = Memo::new(recipe.identity()?, signed_owner.tree);
    let memo_bytes = memo.encode();
    let memo_id = TERRANE_V1.calculate(IdentityKind::Memo, &memo_bytes)?;
    assert_eq!(
        fixture
            .bucket()
            .put(ContentUpload::Meta(MetaUpload::new(
                IdentityKind::Memo,
                &memo_bytes,
            )?))
            .await?,
        memo_id
    );
    assert_eq!(Memo::decode(&memo_bytes)?, memo);
    let old = fixture.snapshot().await?;
    let old_pack = required(
        old.rows
            .get(&members[0].0.terrane_v1_digest()?)
            .ok_or("old selected root"),
    )
    .pack();
    let old_pack_bytes = TokioLocalFs
        .read_nofollow(&fixture.bucket().root().join(old_pack.pack_key()))
        .await?;

    // Ordinary admission intentionally denies reoffered Commit records before
    // store effects. Preserve that real refusal separately from duplicate Memo
    // validation, rather than weakening the producer's staged Commit boundary.
    let mut forbidden = crate::ref_advance::tests::request(vec![first.commit]);
    forbidden.commit.tree = signed_owner.tree;
    forbidden.uploads = vec![StagedUpload::Meta {
        kind: IdentityKind::Commit,
        bytes: old_commit.clone(),
    }];
    fixture.fs.reset();
    let refusal = rejected(fixture.publish(forbidden).await);
    assert_eq!(
        store_failure(&refusal).kind(),
        &StoreErrorKind::Denied {
            verb: "commit",
            pattern: "refs/heads/_/main".into(),
        }
    );
    let rejected_offers = fixture.fs.observations();
    assert!(rejected_offers.pending.is_empty());
    assert!(rejected_offers.committed.is_empty());
    assert!(rejected_offers.raw.is_empty());
    assert!(rejected_offers.mutations.is_empty());
    assert_eq!(fixture.snapshot().await?.state, old.state);
    assert_eq!(
        fixture.bucket().ref_get("refs/heads/_/main").await?,
        Some(first.clone())
    );

    for duplicate in [false, true] {
        fixture.fs.reset();
        let current = required(
            fixture
                .bucket()
                .ref_get("refs/heads/_/main")
                .await?
                .ok_or("current published parent"),
        );
        let mut proposal = crate::ref_advance::tests::request(vec![current.commit]);
        proposal.commit.tree = members[0].0.terrane_v1_digest()?;
        proposal.uploads.clear();
        let prior = fixture.validator.calls(IdentityKind::Memo, &memo_bytes);
        if duplicate {
            // Snapshot rejects duplicate Nodes, and admission rejects Commit
            // offers. Duplicate advisory Memo offers lawfully reach the real
            // batch validator without introducing any permission evidence.
            for _ in 0..2 {
                proposal.uploads.push(StagedUpload::Meta {
                    kind: IdentityKind::Memo,
                    bytes: memo_bytes.clone(),
                });
            }
        }
        let next = fixture.publish(proposal).await?;
        let observations = fixture.fs.observations();
        assert_eq!(
            observations.raw.len(),
            1,
            "empty/all-existing run emitted another catalog"
        );
        assert_eq!(observations.pending.len(), 2);
        assert_eq!(observations.committed.len(), 2);
        if duplicate {
            assert!(fixture.validator.calls(IdentityKind::Memo, &memo_bytes) >= prior + 2);
        }
        assert_eq!(
            TokioLocalFs
                .read_nofollow(&fixture.bucket().root().join(old_pack.pack_key()))
                .await?,
            old_pack_bytes
        );
        assert_eq!(
            fixture.bucket().get(&old_commit_id, None).await?,
            old_commit
        );
        let selected = fixture.snapshot().await?;
        assert_eq!(fixture.bucket().get(&memo_id, None).await?, memo_bytes);
        assert_eq!(
            selected.rows.get(&memo_id.terrane_v1_digest()?),
            old.rows.get(&memo_id.terrane_v1_digest()?)
        );
        assert_eq!(
            selected.rows.get(&members[0].0.terrane_v1_digest()?),
            old.rows.get(&members[0].0.terrane_v1_digest()?)
        );
        let old_inventory = required(
            old.manifest
                .as_ref()
                .and_then(|manifest| manifest.inventory.as_ref())
                .ok_or("old inventory"),
        );
        let inventory = required(
            selected
                .manifest
                .as_ref()
                .and_then(|manifest| manifest.inventory.as_ref())
                .ok_or("new inventory"),
        );
        assert!(old_inventory.iter().all(|entry| inventory.contains(entry)));
        assert_eq!(
            fixture.bucket().ref_get("refs/heads/_/main").await?,
            Some(next)
        );
    }

    // Invalid schema and a genuine declared unavailable Chunk each fail before
    // the run creates any pair, regardless of otherwise valid earlier members.
    for dependency in [false, true] {
        let before = fixture.bucket().ref_get("refs/heads/_/main").await?;
        let current = required(before.as_ref().ok_or("current ref"));
        let (mut proposal, _) = request(vec![current.commit], &[28])?;
        if dependency {
            let file =
                crate::ref_advance::tests::request_file(Vec::new(), b"batch-only missing chunk");
            proposal
                .uploads
                .extend(file.uploads.into_iter().filter(|upload| {
                    matches!(
                        upload,
                        StagedUpload::Meta {
                            kind: IdentityKind::Node,
                            ..
                        }
                    )
                }));
        } else {
            proposal.uploads.push(StagedUpload::Meta {
                kind: IdentityKind::Memo,
                bytes: vec![0xff],
            });
        }
        fixture.fs.reset();
        let error = rejected(fixture.publish(proposal).await);
        upload_failure(&error);
        let observations = fixture.fs.observations();
        assert!(observations.pending.is_empty());
        assert!(observations.raw.is_empty());
        assert_eq!(fixture.bucket().ref_get("refs/heads/_/main").await?, before);
    }
    Ok(())
}

#[tokio::test]
async fn native_meta_batch_preserves_direct_container_and_actual_repair_fallback() -> TestResult {
    let fixture = Fixture::new().await?;
    let orphan = node(27)?;
    put(fixture.bucket(), &orphan).await?;
    let (first, _) = request(Vec::new(), &[])?;
    let first = fixture.publish(first).await?;
    let before = fixture.snapshot().await?;
    let orphan_row = required(
        before
            .rows
            .get(&orphan.0.terrane_v1_digest()?)
            .ok_or("orphan selected row"),
    );
    let direct_pack = TokioLocalFs
        .read_nofollow(&fixture.bucket().root().join(orphan_row.pack().pack_key()))
        .await?;
    let direct_index = TokioLocalFs
        .read_nofollow(&fixture.bucket().root().join(orphan_row.pack().index_key()))
        .await?;

    // The whole direct-container attempt stays on the existing generic path.
    // Distinct new Nodes therefore get ordinary separate packs, not one batch.
    let (mut proposal, members) = request(vec![first.commit], &[26, 25])?;
    proposal.uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Pack,
        bytes: direct_pack.clone(),
    });
    proposal.uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Index,
        bytes: direct_index.clone(),
    });
    fixture.fs.reset();
    let next = fixture.publish(proposal).await?;
    let selected = fixture.snapshot().await?;
    let left = required(
        selected
            .rows
            .get(&members[1].0.terrane_v1_digest()?)
            .ok_or("first new node"),
    );
    let right = required(
        selected
            .rows
            .get(&members[2].0.terrane_v1_digest()?)
            .ok_or("second new node"),
    );
    assert_ne!(left.pack(), right.pack());
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&fixture.bucket().root().join(orphan_row.pack().pack_key()))
            .await?,
        direct_pack
    );
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&fixture.bucket().root().join(orphan_row.pack().index_key()))
            .await?,
        direct_index
    );

    // Only the unrelated genuinely selected orphan's pack is lost; current
    // signed history/root remain served. The verified present detached index
    // and exact old Live row qualify ordinary repair, never generic Corrupt.
    let before_repair = fixture.snapshot().await?;
    TokioLocalFs
        .remove_file(&fixture.bucket().root().join(orphan_row.pack().pack_key()))
        .await?;
    let (mut repair, _) = request(vec![next.commit], &[])?;
    repair.uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Node,
        bytes: orphan.1.clone(),
    });
    fixture.fs.reset();
    let error = rejected(fixture.publish(repair).await);
    assert_eq!(
        store_failure(&error).kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    let after = fixture.snapshot().await?;
    assert_eq!(
        after.state.loss_generation,
        before_repair.state.loss_generation + 1
    );
    assert!(after.state.sources.is_empty());
    assert_eq!(after.state.branches, before_repair.state.branches);
    assert_eq!(after.state.guard, before_repair.state.guard);
    assert_eq!(after.state.burn_owners, before_repair.state.burn_owners);
    assert_eq!(
        fixture.bucket().ref_get("refs/heads/_/main").await?,
        Some(next)
    );
    let repaired = required(
        after
            .rows
            .get(&orphan.0.terrane_v1_digest()?)
            .ok_or("repaired selected Node"),
    );
    assert_ne!(repaired.pack(), orphan_row.pack());
    assert_eq!(fixture.bucket().get(&orphan.0, None).await?, orphan.1);
    assert_eq!(fixture.fs.observations().committed.len(), 2);

    // A present corrupt or genuinely unavailable unrelated placement must
    // propagate its own physical subject, never enter missing-placement repair.
    for unavailable in [false, true] {
        let fixture = Fixture::new().await?;
        let offered = node(17)?;
        put(fixture.bucket(), &offered).await?;
        let (seed, _) = request(Vec::new(), &[])?;
        let first = fixture.publish(seed).await?;
        let before = fixture.snapshot().await?;
        let row = required(
            before
                .rows
                .get(&offered.0.terrane_v1_digest()?)
                .ok_or("orphan Live placement"),
        );
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
                .ok_or("actual old pair inventory"),
        );
        let pack = fixture.bucket().root().join(row.pack().pack_key());
        fixture.fs.reset();
        if unavailable {
            fixture.fs.unavailable(pack.clone());
        } else {
            let mut bytes = TokioLocalFs.read_nofollow(&pack).await?;
            bytes[0] ^= 1;
            std::fs::write(&pack, bytes)?;
        }
        let (mut proposal, _) = request(vec![first.commit], &[])?;
        proposal.uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes: offered.1,
        });
        let error = rejected(fixture.publish(proposal).await);
        let failure = store_failure(&error);
        if unavailable {
            assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
            assert_eq!(
                required(failure.source().ok_or("exact unavailable read source")).to_string(),
                "batch fixture exact nofollow read unavailable"
            );
        } else {
            assert_eq!(
                failure.kind(),
                &StoreErrorKind::Corrupt(CorruptSubject::Identity(
                    TERRANE_V1.from_digest(IdentityKind::Pack, &inventory.pack_hash)?
                ))
            );
        }
        assert!(fixture.fs.observations().pending.is_empty());
        assert!(fixture.fs.observations().raw.is_empty());
        assert_eq!(
            fixture.bucket().ref_get("refs/heads/_/main").await?,
            Some(first)
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_meta_batch_creator_and_catalog_errors_never_acknowledge_members() -> TestResult {
    for (phase, action, acknowledgment) in [
        (
            Phase::Pending,
            Action::Noop,
            Some("native Pending durability unavailable"),
        ),
        (
            Phase::Artifact,
            Action::Fault {
                fault: EffectFault::BeforeFileSync,
                swallow: false,
            },
            None,
        ),
        (
            Phase::Committed,
            Action::Fault {
                fault: EffectFault::BeforeRename,
                swallow: false,
            },
            None,
        ),
        (
            Phase::Raw,
            Action::Noop,
            Some("native raw publication acknowledgment unavailable"),
        ),
        (
            Phase::Raw,
            Action::Fault {
                fault: EffectFault::BeforeFileSync,
                swallow: true,
            },
            Some("native raw publication acknowledgment unavailable"),
        ),
        (
            Phase::Raw,
            Action::Fault {
                fault: EffectFault::AfterFileSync,
                swallow: true,
            },
            Some("native raw publication acknowledgment unavailable"),
        ),
    ] {
        let fixture = Fixture::new().await?;
        let (proposal, members) = request(Vec::new(), &[24, 23])?;
        fixture.fs.arm(phase, action);

        let error = rejected(fixture.publish(proposal).await);

        if let Some(message) = acknowledgment {
            acknowledgment_failure(&error, message);
        } else {
            let failure = store_failure(&error);
            assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
            assert!(
                required(failure.source().ok_or("real native sync source"))
                    .to_string()
                    .starts_with("injected creation")
            );
        }
        let observations = fixture.fs.observations();
        assert_eq!(observations.reached, vec![phase]);
        assert_eq!(fixture.bucket().ref_get("refs/heads/_/main").await?, None);
        if phase == Phase::Raw {
            assert_eq!(
                observations.committed.len(),
                2,
                "Raw selected before genuine creator receipts"
            );
            // Raw rename can precede its failed final ACK. Honest observation
            // permits indeterminate member selection, never fabricated rollback.
            let selected = fixture.snapshot().await?;
            for (identity, _) in members {
                if let Some(row) = selected.rows.get(&identity.terrane_v1_digest()?) {
                    assert!(
                        observations
                            .committed
                            .iter()
                            .any(|(_, journal)| journal.key == row.pack().pack_key())
                    );
                }
            }
        } else {
            assert!(observations.raw.is_empty());
            assert!(fixture.snapshot().await?.rows.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_meta_batch_rechecks_current_original_and_deadline_before_ack() -> TestResult {
    for phase in [Phase::Pending, Phase::Raw, Phase::Mutation] {
        for selected_guard in [false, true] {
            let fixture = Arc::new(Fixture::new().await?);
            let (seed, _) = request(Vec::new(), &[])?;
            let first = fixture.publish(seed).await?;
            let before = fixture.snapshot().await?;
            let target = if selected_guard {
                required(before.guard.clone().ok_or("selected protected Guard"))
            } else {
                fixture.original.join("registration.cbor")
            };
            let (proposal, members) = request(vec![first.commit], &[22])?;
            fixture.fs.reset();
            let (arrived, release, after) = fixture.fs.pause(phase);
            let running = fixture.clone();
            let task = tokio::spawn(async move { running.publish(proposal).await });
            wait(arrived).await?;
            replace(&target)?;
            required(release.send(()));

            let error = rejected(task.await?);

            let failure = store_failure(&error);
            assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
            let cause = required(failure.source().ok_or("preserved queued physical failure"));
            assert!(matches!(
                cause.to_string().as_str(),
                "exact read metadata changed"
                    | "physical preimage changed"
                    | "exact read pathname changed"
                    | "current physical fence changed"
            ));
            assert!(
                after.try_recv().is_err(),
                "sync occurred after changed protected incarnation"
            );
            assert_eq!(fixture.fs.observations().reached, vec![phase]);
            if phase == Phase::Mutation {
                let selected = fixture
                    .assert_final_mutation(&members[0].0, Some(&first), &before.backend)
                    .await?;
                match &error {
                    RepositoryError::Advance(AdvanceError::Indeterminate { observed, .. }) => {
                        assert_eq!(required(observed.as_ref()).as_deref(), Some(&selected));
                    }
                    other => panic!("expected post-slot native indeterminate refusal: {other:?}"),
                }
            } else {
                assert_eq!(
                    fixture.bucket().ref_get("refs/heads/_/main").await?,
                    Some(first)
                );
            }
        }
    }
    for phase in [Phase::Pending, Phase::Raw, Phase::Mutation] {
        let clock = expiry_clock();
        let fixture = Fixture::with_clock(clock.clone()).await?;
        let (proposal, members) = request(Vec::new(), &[21])?;
        let before = fixture.snapshot().await?;
        assert_eq!(clock.monotonic(), Duration::ZERO);
        fixture.fs.arm(phase, Action::Expire(clock.clone()));

        let error = rejected(fixture.publish(proposal).await);

        assert_eq!(clock.monotonic(), Duration::from_secs(31));

        if phase == Phase::Mutation {
            assert!(matches!(
                error,
                RepositoryError::Advance(AdvanceError::Expired)
            ));
        } else {
            let failure = store_failure(&error);
            assert!(matches!(failure.kind(), StoreErrorKind::Denied { .. }));
            // STORE-30 suppresses diagnostic detail for every denial, including
            // a genuinely retained deadline refusal at the native worker.
            assert!(failure.source().is_none());
            assert_eq!(fixture.fs.observations().errors, vec![failure.to_string()]);
        }
        assert_eq!(fixture.fs.observations().reached, vec![phase]);
        if phase == Phase::Mutation {
            fixture
                .assert_final_mutation(&members[0].0, None, &before.backend)
                .await?;
        } else {
            assert_eq!(fixture.bucket().ref_get("refs/heads/_/main").await?, None);
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_meta_batch_cancelled_and_partial_runs_keep_native_receipts_honest() -> TestResult {
    for phase in [Phase::Pending, Phase::Raw] {
        let fixture = Arc::new(Fixture::new().await?);
        let (proposal, _) = request(Vec::new(), &[20, 19])?;
        let original_lock = fixture.original.join("retention.lock");
        let namespace_lock = fixture
            .bucket()
            .root()
            .join(BucketKey::parse("CAPABILITIES")?.lock_name());
        let (arrived, release, after) = fixture.fs.pause(phase);
        let running = fixture.clone();
        let task = tokio::spawn(async move { running.publish(proposal).await });
        wait(arrived).await?;
        still_excluded(&[namespace_lock.clone(), original_lock.clone()])?;
        task.abort();
        let cancelled = rejected(task.await);
        assert!(cancelled.is_cancelled());
        // The actual submitted worker keeps both genuine exclusions after its
        // asynchronous caller has disappeared. No receipt is constructed here.
        still_excluded(&[namespace_lock, original_lock])?;
        required(release.send(()));
        wait(after).await?;
        assert_eq!(fixture.bucket().ref_get("refs/heads/_/main").await?, None);
        assert_eq!(fixture.fs.observations().reached, vec![phase]);
    }

    let fixture = Fixture::new().await?;
    let (mut proposal, _) = request(Vec::new(), &[18])?;
    let file =
        crate::ref_advance::tests::request_file(Vec::new(), b"durable preceding ordinary chunk");
    let chunk = required(
        file.uploads
            .into_iter()
            .find(|upload| matches!(upload, StagedUpload::Chunk { .. }))
            .ok_or("actual encoded Chunk offer"),
    );
    let (identity, encoded) = match &chunk {
        StagedUpload::Chunk {
            identity, encoded, ..
        } => (identity.clone(), encoded.clone()),
        _ => unreachable!("selected exact Chunk variant"),
    };
    proposal.uploads.insert(0, chunk);
    proposal.uploads.push(StagedUpload::Meta {
        kind: IdentityKind::Memo,
        bytes: vec![0xff],
    });
    fixture.fs.reset();

    let error = rejected(fixture.publish(proposal).await);

    upload_failure(&error);
    assert_eq!(fixture.bucket().get(&identity, None).await?, encoded);
    assert_eq!(fixture.bucket().ref_get("refs/heads/_/main").await?, None);
    let observations = fixture.fs.observations();
    assert_eq!(observations.pending.len(), 2);
    assert_eq!(observations.committed.len(), 2);
    assert_eq!(observations.raw.len(), 1);
    let selected = fixture.snapshot().await?;
    assert_eq!(selected.rows.len(), 1);
    assert!(selected.rows.contains_key(&identity.terrane_v1_digest()?));
    Ok(())
}
