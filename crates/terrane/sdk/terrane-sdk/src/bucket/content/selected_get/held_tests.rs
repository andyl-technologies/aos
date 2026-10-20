//! Exercises held reads through actual native and unsupported-hook bindings.
//!
//! Native closing faults occur after verification while the original namespace
//! remains held. Scalar faults occur at actual bounded reads and claim only
//! visible-input checking. Both paths retain current selected-chain checks.

use super::*;
use crate::bucket::content::ranged_pack::tests::support::{Fixture, ReadProfile, TestResult};
use crate::bucket::content_observation::GetClosePause;
use crate::bucket::tests::{Bucket, control_path, fixture};
use crate::pack::MergedShard;
use crate::store::{ChunkUpload, MetaUpload, TokioLocalFs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

struct PausedHeldGet {
    pause: Arc<GetClosePause>,
    request: tokio::task::JoinHandle<Result<Vec<u8>, StoreFailure>>,
}

impl PausedHeldGet {
    async fn start<F, C, V>(
        bucket: &FileBucket<F, C, V>,
        identity: &Identity,
        range: Option<ByteRange>,
        writable: bool,
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        F: LocalFs + BucketBinding + 'static,
        C: Clock + BucketBinding + 'static,
        V: ContentValidator + BucketBinding + 'static,
    {
        let pause = bucket.observe_content_for_tests().pause_next_get();
        let bucket = bucket.clone();
        let identity = identity.clone();
        let request = tokio::spawn(async move {
            let holder = SingleHeld::acquire_read_only(&bucket).await?;
            if writable {
                holder.destination().get(&identity, range).await
            } else {
                holder.source().get(&identity, range).await
            }
        });
        if let Err(error) =
            tokio::time::timeout(std::time::Duration::from_secs(10), pause.arrived.notified()).await
        {
            request.abort();
            let outcome = request.await;
            return Err(
                format!("held GET did not reach closing checks: {error}; {outcome:?}").into(),
            );
        }
        Ok(Self { pause, request })
    }

    async fn finish(self) -> Result<Result<Vec<u8>, StoreFailure>, Box<dyn std::error::Error>> {
        self.pause.release.notify_one();
        Ok(self.request.await?)
    }
}

async fn replace_equal(path: &Path) -> TestResult {
    let original = tokio::fs::symlink_metadata(path).await?;
    let bytes = TokioLocalFs.read_nofollow(path).await?;
    let replacement = path.with_extension("held-replacement");
    TokioLocalFs.write_new(&replacement, &bytes).await?;
    tokio::fs::set_permissions(&replacement, original.permissions()).await?;
    tokio::fs::rename(&replacement, path).await?;

    let current = tokio::fs::symlink_metadata(path).await?;
    assert_ne!(
        (original.dev(), original.ino()),
        (current.dev(), current.ino())
    );
    assert_eq!(TokioLocalFs.read_nofollow(path).await?, bytes);
    Ok(())
}

async fn replace_directory(path: &Path) -> TestResult {
    let original = tokio::fs::symlink_metadata(path).await?;
    let previous = path.with_extension("held-original");
    tokio::fs::rename(path, &previous).await?;
    tokio::fs::create_dir(path).await?;
    tokio::fs::set_permissions(path, original.permissions()).await?;
    let mut children = tokio::fs::read_dir(previous).await?;
    while let Some(child) = children.next_entry().await? {
        tokio::fs::rename(child.path(), path.join(child.file_name())).await?;
    }

    let current = tokio::fs::symlink_metadata(path).await?;
    assert_ne!(
        (original.dev(), original.ino()),
        (current.dev(), current.ino())
    );
    Ok(())
}

async fn remove(fixture: Fixture) -> TestResult {
    tokio::fs::remove_dir_all(control_path(fixture.bucket.root())).await?;
    fixture.remove().await?;
    Ok(())
}

/// Requires a supported read to identify changed evidence at its actual fence.
fn assert_changed_input_refusal(outcome: &Result<Vec<u8>, StoreFailure>) {
    assert!(
        matches!(outcome, Err(failure) if matches!(failure.kind(),
            StoreErrorKind::Corrupt(_) | StoreErrorKind::Unavailable { .. })),
        "changed actual input did not cause a supported closing refusal: {outcome:?}"
    );
}

#[tokio::test]
async fn held_get_native_and_scalar_ranges_keep_existing_exclusion_and_bounded_io() -> TestResult {
    for profile in [
        ReadProfile::Native,
        ReadProfile::UnsupportedHooks,
        ReadProfile::ReadOnly,
        ReadProfile::Legacy,
    ] {
        let fixture = Fixture::raw_with_profile(b"actual held bounded member", profile).await?;
        if matches!(profile, ReadProfile::Legacy) {
            let index_before = TokioLocalFs.read_nofollow(&fixture.index_path).await?;
            let outcome = SingleHeld::acquire_read_only(&fixture.bucket).await;
            assert!(matches!(outcome, Err(ref failure)
                if matches!(failure.kind(), StoreErrorKind::ReadOnly)));
            assert_eq!(fixture.fs.whole_reads(), 0);
            assert_eq!(fixture.fs.effects(), 0);
            assert_eq!(
                TokioLocalFs.read_nofollow(&fixture.index_path).await?,
                index_before
            );
            fixture.remove().await?;
            continue;
        }

        let range = ByteRange {
            start: 1,
            length: 7,
        };
        for (path, alias) in [
            (&fixture.pack_path, "held-pack-hardlink"),
            (&fixture.index_path, "held-index-hardlink"),
        ] {
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).await?;
            tokio::fs::hard_link(path, fixture.bucket.root().join(alias)).await?;
        }
        let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
        let held = holder.source();
        let before = held.physical_identity();

        assert_eq!(
            held.get(&fixture.identity, Some(range)).await?,
            fixture.encoded[1..8]
        );
        assert_eq!(held.physical_identity(), before);
        assert_eq!(fixture.fs.whole_reads(), 0, "{profile:?}");
        assert_eq!(fixture.fs.effects(), 0, "{profile:?}");
        let member_start = fixture.body_offset()? as u64;
        let member_end = member_start + fixture.encoded.len() as u64;
        let mut member_ranges = fixture
            .fs
            .ranges()?
            .into_iter()
            .filter(|(path, _)| path == &fixture.pack_path)
            .map(|(_, range)| range)
            .collect::<Vec<_>>();
        member_ranges.sort_by_key(|range| range.start);
        let mut covered = member_start;
        for range in member_ranges {
            if range.start > covered {
                break;
            }
            covered = covered.max(range.start + range.length);
        }
        assert!(
            covered >= member_end,
            "{profile:?}: actual member body was not read"
        );
        if matches!(profile, ReadProfile::Native) {
            assert!(!fixture.fs.closing_ranges()?.is_empty());
        } else {
            assert!(fixture.fs.ordinary_range_reads() > 0);
        }
        for invalid in [
            ByteRange {
                start: u64::MAX,
                length: 1,
            },
            ByteRange {
                start: 0,
                length: u64::MAX,
            },
        ] {
            let outcome = held.get(&fixture.identity, Some(invalid)).await;
            assert!(matches!(outcome, Err(ref failure)
                if matches!(failure.kind(), StoreErrorKind::Invalid(InvalidReason::Range(actual)) if actual == &invalid)));
        }

        drop(held);
        drop(holder);
        fixture.fs.check_existing_lock_continuity().await?;
        remove(fixture).await?;
    }
    Ok(())
}

#[tokio::test]
async fn held_get_native_refuses_equal_byte_inputs_after_verification() -> TestResult {
    for fault in 0..5 {
        let fixture = Fixture::raw(b"held retained original inputs").await?;
        let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
        let held = holder.source();
        let observed = held.observe_for_read().await?;
        let catalog = fixture.bucket.catalog_observed(&observed).await?;
        let generation = catalog
            .capabilities
            .generation
            .ok_or("actual generation absent")?;
        let shard = fixture.bucket.root().join(format!(
            "objects/index/{generation}/{}.idx",
            fixture.identity.terrane_v1_digest()?[0]
        ));
        let slot = control_path(fixture.bucket.root())
            .join(format!("publication/commits/{}", observed.state().revision));
        drop(observed);
        drop(held);
        drop(holder);

        // A writable adapter used for read-only work must retain the same read
        // closure without minting a writable receipt or acquiring another lock.
        let paused = PausedHeldGet::start(
            &fixture.bucket,
            &fixture.identity,
            Some(ByteRange {
                start: 1,
                length: 7,
            }),
            fault % 2 == 1,
        )
        .await?;
        match fault {
            0 => replace_equal(&fixture.pack_path).await?,
            1 => replace_equal(&fixture.index_path).await?,
            2 => replace_equal(&shard).await?,
            3 => replace_equal(&slot).await?,
            _ => replace_directory(shard.parent().ok_or("actual shard parent absent")?).await?,
        }
        let outcome = paused.finish().await?;
        assert_changed_input_refusal(&outcome);
        assert_eq!(fixture.fs.whole_reads(), 0);
        assert_eq!(fixture.fs.effects(), 0);
        remove(fixture).await?;
    }
    Ok(())
}

#[tokio::test]
async fn held_get_native_and_scalar_refuse_changed_inputs_during_bounded_consumption() -> TestResult
{
    for profile in [ReadProfile::Native, ReadProfile::UnsupportedHooks] {
        for ancestor in [false, true] {
            let fixture = Fixture::raw_with_profile(b"held real range fault", profile).await?;
            let target = if ancestor {
                fixture
                    .pack_path
                    .parent()
                    .ok_or("actual pack parent absent")?
                    .to_owned()
            } else {
                fixture.pack_path.clone()
            };
            fixture.fs.replace_before_range(target, ancestor)?;
            let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
            let outcome = holder
                .source()
                .get(
                    &fixture.identity,
                    Some(ByteRange {
                        start: 1,
                        length: 7,
                    }),
                )
                .await;

            assert_changed_input_refusal(&outcome);
            assert_eq!(fixture.fs.whole_reads(), 0);
            assert_eq!(fixture.fs.effects(), 0);
            drop(holder);
            remove(fixture).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn held_get_native_failure_never_retries_scalar_and_scalar_short_reads_refuse() -> TestResult
{
    for profile in [ReadProfile::Native, ReadProfile::UnsupportedHooks] {
        let fixture =
            Fixture::raw_with_profile(b"held unsupported is the only fallback", profile).await?;
        let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
        if matches!(profile, ReadProfile::Native) {
            fixture.fs.fail_native_read();
        } else {
            fixture.fs.short_ordinary_read();
        }
        let outcome = holder
            .source()
            .get(
                &fixture.identity,
                Some(ByteRange {
                    start: 1,
                    length: 7,
                }),
            )
            .await;

        assert!(outcome.is_err(), "{profile:?}: {outcome:?}");
        if matches!(profile, ReadProfile::Native) {
            assert_eq!(fixture.fs.ordinary_range_reads(), 0);
        }
        assert_eq!(fixture.fs.whole_reads(), 0);
        assert_eq!(fixture.fs.effects(), 0);
        drop(holder);
        remove(fixture).await?;
    }
    Ok(())
}

async fn admit(
    bucket: &Bucket,
    plaintext: &[u8],
    encoded: &[u8],
) -> Result<Identity, StoreFailure> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .map_err(|_| files::malformed())?;
    bucket
        .put(ContentUpload::Chunk(ChunkUpload {
            encoded,
            identity: &identity,
            declared_plaintext_len: plaintext.len(),
            position: ChunkPosition::Final,
            profile: &bucket.inner.config.chunk_profile,
        }))
        .await
}

#[tokio::test]
async fn held_get_rechecks_actual_selection_and_each_request_under_one_holder() -> TestResult {
    let bucket = fixture().await;
    let plaintext = b"held current selected chain";
    let mut encoded = vec![0];
    encoded.extend_from_slice(plaintext);
    let identity = admit(&bucket, plaintext, &encoded).await?;
    let next_plaintext = b"genuine already-published next selection";
    let mut next_encoded = vec![0];
    next_encoded.extend_from_slice(next_plaintext);
    admit(&bucket, next_plaintext, &next_encoded).await?;
    let (slot, pack) = {
        let holder = SingleHeld::acquire_read_only(&bucket).await?;
        let held = holder.source();
        let observed = held.observe_for_read().await?;
        let catalog = bucket.catalog_observed(&observed).await?;
        (
            control_path(bucket.root())
                .join(format!("publication/commits/{}", observed.state().revision)),
            bucket
                .root()
                .join(bucket.location(&catalog, &identity)?.pack().pack_key()),
        )
    };
    let pending = slot.with_extension("held-pending");
    tokio::fs::rename(&slot, &pending).await?;
    let paused = PausedHeldGet::start(&bucket, &identity, None, false).await?;
    tokio::fs::rename(pending, &slot).await?;
    assert_changed_input_refusal(&paused.finish().await?);

    let holder = SingleHeld::acquire_read_only(&bucket).await?;
    let held = holder.source();
    assert_eq!(held.get(&identity, None).await?, encoded);
    replace_equal(&pack).await?;
    // A completed call leaves no selected or decoded authority in the holder.
    assert_eq!(held.get(&identity, None).await?, encoded);
    let mut corrupt = TokioLocalFs.read_nofollow(&pack).await?;
    *corrupt.last_mut().ok_or("actual pack is empty")? ^= 1;
    tokio::fs::write(&pack, corrupt).await?;
    assert!(matches!(held.get(&identity, None).await,
        Err(ref failure) if matches!(failure.kind(), StoreErrorKind::Corrupt(_))));

    drop(held);
    drop(holder);
    tokio::fs::remove_dir_all(control_path(bucket.root())).await?;
    tokio::fs::remove_dir_all(bucket.root()).await?;
    Ok(())
}

#[tokio::test]
async fn held_get_native_and_scalar_verify_dictionary_dependency_and_native_closing() -> TestResult
{
    for profile in [ReadProfile::Native, ReadProfile::UnsupportedHooks] {
        let fixture = Fixture::dictionary(profile).await?;
        let dictionary = match parse_envelope(&fixture.encoded)?.codec {
            Codec::ZstdDictionary(hash) => hash,
            _ => return Err("actual dictionary fixture was lost".into()),
        };
        let dictionary_location = fixture
            .bucket
            .catalog()
            .await?
            .shards
            .into_iter()
            .flat_map(|shard| shard.entries().to_vec())
            .find(|entry| entry.entry().hash() == &dictionary)
            .ok_or("actual dictionary placement absent")?;
        let dictionary_path = fixture
            .bucket
            .root()
            .join(dictionary_location.pack().pack_key());
        let range = ByteRange {
            start: 1,
            length: 5,
        };
        {
            let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
            assert_eq!(
                holder.source().get(&fixture.identity, Some(range)).await?,
                fixture.encoded[1..6]
            );
        }
        assert!(
            fixture
                .fs
                .ranges()?
                .iter()
                .any(|(path, _)| path == &dictionary_path)
        );
        if matches!(profile, ReadProfile::Native) {
            let paused =
                PausedHeldGet::start(&fixture.bucket, &fixture.identity, Some(range), false)
                    .await?;
            replace_equal(&dictionary_path).await?;
            assert_changed_input_refusal(&paused.finish().await?);
        }
        let mut pack = TokioLocalFs.read_nofollow(&dictionary_path).await?;
        let last = usize::try_from(dictionary_location.entry().offset())?
            + dictionary_location.entry().body_len() as usize
            - 1;
        pack[last] ^= 1;
        tokio::fs::write(dictionary_path, pack).await?;
        let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
        assert!(
            matches!(holder.source().get(&fixture.identity, Some(range)).await,
            Err(ref failure) if matches!(failure.kind(), StoreErrorKind::Corrupt(_)))
        );
        assert_eq!(fixture.fs.whole_reads(), 0);
        assert_eq!(fixture.fs.effects(), 0);

        drop(holder);
        remove(fixture).await?;
    }
    Ok(())
}

#[tokio::test]
async fn held_get_cancellation_releases_request_inputs_and_namespace() -> TestResult {
    let fixture = Fixture::raw(b"cancelled held read original inputs").await?;
    let range = ByteRange {
        start: 1,
        length: 7,
    };
    let paused =
        PausedHeldGet::start(&fixture.bucket, &fixture.identity, Some(range), false).await?;
    paused.request.abort();
    assert!(paused.request.await.is_err());

    replace_equal(&fixture.pack_path).await?;
    let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
    assert_eq!(
        holder.source().get(&fixture.identity, Some(range)).await?,
        fixture.encoded[1..8]
    );
    assert_eq!(fixture.fs.whole_reads(), 0);
    assert_eq!(fixture.fs.effects(), 0);

    drop(holder);
    remove(fixture).await
}

/// Retains a genuine canonical Node and its actually selected artifact paths.
struct AuxiliaryFixture {
    bucket: Bucket,
    identity: Identity,
    bytes: Vec<u8>,
    pack: std::path::PathBuf,
    index: std::path::PathBuf,
    shard: std::path::PathBuf,
    slot: std::path::PathBuf,
}

fn auxiliary_node(
    explicit_properties: bool,
) -> Result<(Identity, Vec<u8>), Box<dyn std::error::Error>> {
    let tree = terrane_format::tree_builder::Tree::build(
        Vec::new(),
        explicit_properties.then(Vec::new),
        262144,
        terrane_format::tree_format::TreeUse::Ordinary,
    )?;
    let bytes = tree
        .nodes()
        .next()
        .ok_or("canonical auxiliary tree has no Node")?
        .encoded()
        .to_vec();
    Ok((TERRANE_V1.calculate(IdentityKind::Node, &bytes)?, bytes))
}

impl AuxiliaryFixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let bucket = fixture().await;
        let (identity, bytes) = auxiliary_node(false)?;
        assert_eq!(
            bucket
                .put(ContentUpload::Meta(MetaUpload::new(
                    IdentityKind::Node,
                    &bytes
                )?))
                .await?,
            identity
        );
        let holder = SingleHeld::acquire_read_only(&bucket).await?;
        let held = holder.source();
        let observed = held.observe_publication_ordinary_retained().await?;
        let catalog = bucket.catalog_observed(&observed).await?;
        let location = bucket.location(&catalog, &identity)?;
        let pack = bucket.root().join(location.pack().pack_key());
        let index = bucket.root().join(location.pack().index_key());
        let generation = catalog
            .capabilities
            .generation
            .ok_or("selected generation absent")?;
        let shard = bucket.root().join(format!(
            "objects/index/{generation}/{}.idx",
            identity.terrane_v1_digest()?[0]
        ));
        let slot = control_path(bucket.root())
            .join(format!("publication/commits/{}", observed.state().revision));
        drop(observed);
        drop(held);
        drop(holder);
        Ok(Self {
            bucket,
            identity,
            bytes,
            pack,
            index,
            shard,
            slot,
        })
    }

    async fn remove(self) -> TestResult {
        tokio::fs::remove_dir_all(control_path(self.bucket.root())).await?;
        tokio::fs::remove_dir_all(self.bucket.root()).await?;
        Ok(())
    }
}

#[tokio::test]
async fn index_auxiliary_placement_distinguishes_unplaced_and_present_nodes() -> TestResult {
    let fixture = AuxiliaryFixture::new().await?;
    let (unplaced, _) = auxiliary_node(true)?;
    assert_ne!(unplaced, fixture.identity);
    let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
    let held = holder.source();
    let observed = held.observe_publication_ordinary_retained().await?;

    assert_eq!(
        held.index_auxiliary_placement(&observed, &unplaced).await?,
        None
    );
    assert!(
        matches!(held.index_auxiliary_absent(&observed, &unplaced).await,
        Err(ref error) if matches!(error.kind(), StoreErrorKind::Absent(actual) if actual == &unplaced))
    );
    assert!(matches!(held.get(&unplaced, None).await,
        Err(ref error) if matches!(error.kind(), StoreErrorKind::Absent(actual) if actual == &unplaced)));
    assert_eq!(
        held.index_auxiliary_placement(&observed, &fixture.identity)
            .await?,
        Some(false)
    );
    assert!(
        !held
            .index_auxiliary_absent(&observed, &fixture.identity)
            .await?
    );
    assert_eq!(held.get(&fixture.identity, None).await?, fixture.bytes);

    drop(observed);
    drop(held);
    drop(holder);
    fixture.remove().await
}

#[tokio::test]
async fn index_auxiliary_placement_reports_only_closed_selected_artifact_loss() -> TestResult {
    for (missing_pack, missing_index) in [(true, false), (false, true), (true, true)] {
        let fixture = AuxiliaryFixture::new().await?;
        if missing_pack {
            tokio::fs::remove_file(&fixture.pack).await?;
        }
        if missing_index {
            tokio::fs::remove_file(&fixture.index).await?;
        }
        let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
        let held = holder.source();
        let observed = held.observe_publication_ordinary_retained().await?;

        assert_eq!(
            held.index_auxiliary_placement(&observed, &fixture.identity)
                .await?,
            Some(true)
        );
        assert!(
            held.index_auxiliary_absent(&observed, &fixture.identity)
                .await?
        );
        assert!(held.get(&fixture.identity, None).await.is_err());

        drop(observed);
        drop(held);
        drop(holder);
        fixture.remove().await?;
    }
    Ok(())
}

#[tokio::test]
async fn index_auxiliary_placement_refuses_corrupt_present_companions() -> TestResult {
    for missing_pack in [false, true] {
        let fixture = AuxiliaryFixture::new().await?;
        let (missing, present) = if missing_pack {
            (&fixture.pack, &fixture.index)
        } else {
            (&fixture.index, &fixture.pack)
        };
        tokio::fs::remove_file(missing).await?;
        let mut bytes = TokioLocalFs.read_nofollow(present).await?;
        *bytes.last_mut().ok_or("selected companion is empty")? ^= 1;
        tokio::fs::write(present, bytes).await?;
        let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
        let held = holder.source();
        let observed = held.observe_publication_ordinary_retained().await?;

        for result in [
            held.index_auxiliary_placement(&observed, &fixture.identity)
                .await
                .map(|_| ()),
            held.index_auxiliary_absent(&observed, &fixture.identity)
                .await
                .map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(ref error) if matches!(error.kind(), StoreErrorKind::Corrupt(_)))
            );
        }

        drop(observed);
        drop(held);
        drop(holder);
        fixture.remove().await?;
    }
    Ok(())
}

#[tokio::test]
async fn index_auxiliary_placement_refuses_foreign_observations_and_non_nodes() -> TestResult {
    let fixture = AuxiliaryFixture::new().await?;
    let foreign = AuxiliaryFixture::new().await?;
    let holder = SingleHeld::acquire_read_only(&fixture.bucket).await?;
    let other_holder = SingleHeld::acquire_read_only(&foreign.bucket).await?;
    let held = holder.source();
    let other_held = other_holder.source();
    let observed = held.observe_publication_ordinary_retained().await?;
    let other_observed = other_held.observe_publication_ordinary_retained().await?;

    assert!(
        matches!(held.index_auxiliary_placement(&other_observed, &fixture.identity).await,
        Err(ref error) if matches!(error.kind(), StoreErrorKind::Corrupt(_)))
    );
    let chunk = TERRANE_V1.calculate(IdentityKind::Chunk, b"not an auxiliary Node")?;
    assert!(
        matches!(held.index_auxiliary_placement(&observed, &chunk).await,
        Err(ref error) if matches!(error.kind(), StoreErrorKind::Unsupported))
    );

    drop(other_observed);
    drop(observed);
    drop(other_held);
    drop(held);
    drop(other_holder);
    drop(holder);
    foreign.remove().await?;
    fixture.remove().await
}

#[derive(Clone, Copy, Debug)]
enum UnservedAuxiliary {
    Tombstone,
    Quarantine,
    WrongKind,
    ExcludedPack,
}

#[tokio::test]
async fn index_auxiliary_placement_refuses_existing_unserved_catalog_rows() -> TestResult {
    for fault in [
        UnservedAuxiliary::Tombstone,
        UnservedAuxiliary::Quarantine,
        UnservedAuxiliary::WrongKind,
        UnservedAuxiliary::ExcludedPack,
    ] {
        let fixture = AuxiliaryFixture::new().await?;
        let holder = SingleHeld::acquire(&fixture.bucket).await?;
        let held = holder.destination();
        let observed = held.observe_publication().await?;
        let catalog = fixture.bucket.catalog_observed(&observed).await?;
        let generation = fixture.bucket.next_generation(&catalog).await?;
        let hash = fixture.identity.terrane_v1_digest()?;
        let mut shards = Vec::new();
        for shard in &catalog.shards {
            let mut records =
                terrane_format::pack_format::decode_shard(&shard.encode(), shard.shard())?;
            if let Some(position) = records.iter().position(|record| record.record.hash == hash) {
                match fault {
                    UnservedAuxiliary::Tombstone => {
                        records[position].state = RecordState::Tombstone as u8
                    }
                    UnservedAuxiliary::Quarantine => {
                        records[position].state = RecordState::Quarantine as u8
                    }
                    UnservedAuxiliary::WrongKind => {
                        records[position].record.kind = EntryKind::Commit as u8
                    }
                    UnservedAuxiliary::ExcludedPack => {
                        // An exact legacy Tombstone row fences its whole pack.
                        // Keep the target Live while publishing that separate
                        // nominal row through the actual Raw selected protocol;
                        // this constructs no collection or restore authority.
                        let mut tombstone = records[position].clone();
                        tombstone.record.hash[31] ^= 1;
                        tombstone.state = RecordState::Tombstone as u8;
                        records.push(tombstone);
                        records.sort_by_key(|record| record.record.hash);
                    }
                }
            }
            shards.push(MergedShard::decode(
                &terrane_format::pack_format::encode_shard(&records),
                generation,
                shard.shard(),
            )?);
        }
        fixture
            .bucket
            .publish_shards_held(&held, &observed, catalog, generation, &shards)
            .await?;
        drop(observed);
        let observed = held.observe_for_read_ordinary_retained().await?;
        let selected = fixture.bucket.catalog_observed(&observed).await?;
        assert!(
            selected
                .shards
                .iter()
                .flat_map(|shard| shard.entries())
                .any(|row| row.entry().hash() == &hash),
            "{fault:?}"
        );

        for result in [
            held.index_auxiliary_placement(&observed, &fixture.identity)
                .await
                .map(|_| ()),
            held.index_auxiliary_absent(&observed, &fixture.identity)
                .await
                .map(|_| ()),
            held.get(&fixture.identity, None).await.map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(ref error)
                if matches!(error.kind(), StoreErrorKind::Absent(actual) if actual == &fixture.identity)),
                "{fault:?}: {result:?}"
            );
        }

        drop(observed);
        drop(held);
        drop(holder);
        fixture.remove().await?;
    }
    Ok(())
}

struct PausedAuxiliaryPlacement {
    pause: Arc<GetClosePause>,
    request: tokio::task::JoinHandle<Result<Option<bool>, StoreFailure>>,
}

impl PausedAuxiliaryPlacement {
    async fn start(
        bucket: &Bucket,
        identity: &Identity,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pause = bucket.observe_content_for_tests().pause_next_get();
        let bucket = bucket.clone();
        let identity = identity.clone();
        let request = tokio::spawn(async move {
            let holder = SingleHeld::acquire_read_only(&bucket).await?;
            let held = holder.source();
            let observed = held.observe_publication_ordinary_retained().await?;
            held.index_auxiliary_placement(&observed, &identity).await
        });
        if let Err(error) =
            tokio::time::timeout(std::time::Duration::from_secs(10), pause.arrived.notified()).await
        {
            request.abort();
            let outcome = request.await;
            return Err(
                format!("auxiliary check did not reach closing: {error}; {outcome:?}").into(),
            );
        }
        Ok(Self { pause, request })
    }

    async fn finish(
        self,
    ) -> Result<Result<Option<bool>, StoreFailure>, Box<dyn std::error::Error>> {
        self.pause.release.notify_one();
        Ok(self.request.await?)
    }
}

#[tokio::test]
async fn index_auxiliary_placement_refuses_catalog_changes_for_all_states() -> TestResult {
    for state in [None, Some(false), Some(true)] {
        for ancestor in [false, true] {
            let fixture = AuxiliaryFixture::new().await?;
            let identity = if state.is_none() {
                auxiliary_node(true)?.0
            } else {
                fixture.identity.clone()
            };
            if state == Some(true) {
                tokio::fs::remove_file(&fixture.pack).await?;
            }
            let paused = PausedAuxiliaryPlacement::start(&fixture.bucket, &identity).await?;
            if ancestor {
                replace_directory(
                    fixture
                        .shard
                        .parent()
                        .ok_or("selected shard parent absent")?,
                )
                .await?;
            } else {
                replace_equal(&fixture.shard).await?;
            }

            let result = paused.finish().await?;
            assert!(
                matches!(result, Err(ref error) if matches!(error.kind(),
                StoreErrorKind::Corrupt(_) | StoreErrorKind::Unavailable { .. })),
                "{state:?}, ancestor={ancestor}: {result:?}"
            );
            fixture.remove().await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn index_auxiliary_placement_refuses_selection_changes_and_reappearance() -> TestResult {
    let fixture = AuxiliaryFixture::new().await?;
    let pending = fixture.slot.with_extension("auxiliary-pending");
    tokio::fs::rename(&fixture.slot, &pending).await?;
    let (unplaced, _) = auxiliary_node(true)?;
    let paused = PausedAuxiliaryPlacement::start(&fixture.bucket, &unplaced).await?;
    tokio::fs::rename(pending, &fixture.slot).await?;
    let result = paused.finish().await?;
    assert!(
        matches!(result, Err(ref error) if matches!(error.kind(),
        StoreErrorKind::Corrupt(_) | StoreErrorKind::Unavailable { .. })),
        "{result:?}"
    );
    fixture.remove().await?;

    let fixture = AuxiliaryFixture::new().await?;
    let original = TokioLocalFs.read_nofollow(&fixture.pack).await?;
    tokio::fs::remove_file(&fixture.pack).await?;
    let paused = PausedAuxiliaryPlacement::start(&fixture.bucket, &fixture.identity).await?;
    TokioLocalFs.write_new(&fixture.pack, &original).await?;
    let result = paused.finish().await?;
    assert!(
        matches!(result, Err(ref error) if matches!(error.kind(),
        StoreErrorKind::Corrupt(_) | StoreErrorKind::Unavailable { .. })),
        "{result:?}"
    );
    fixture.remove().await
}
