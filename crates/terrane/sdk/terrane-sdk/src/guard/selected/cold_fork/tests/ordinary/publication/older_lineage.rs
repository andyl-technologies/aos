//! Reconstructs exact acknowledged older-lineage fork state from native snapshots.

use super::*;

/// Retains the independently selected state and whole logical preimages before a cold Candidate.
pub(super) struct PriorForkSelection {
    /// Contains the exact prior transaction state verified by the native chain.
    pub(super) state: terrane_format::gc::publication::PublicationState,
    /// Contains complete prior logical values, retaining explicit absence tombstones.
    pub(super) logical: std::collections::BTreeMap<String, Option<Vec<u8>>>,
}

/// Reads the actual immutable snapshot preceding the acknowledged cold Candidate.
///
/// # Errors
/// Returns errors for unavailable selected controls, missing actual transactions,
/// malformed snapshots, invalid predecessor edges, or unavailable physical reads.
///
/// # Panics
/// Panics when the actual selected transaction, snapshot identity, canonical bytes,
/// or retained physical incarnation contradicts the independently observed chain.
pub(super) async fn prior_fork_selection(
    repository: &NativeRepository,
    clock: &TestClock,
    acknowledged: &terrane_format::gc::publication::PublicationTransaction,
) -> TestResult<PriorForkSelection> {
    use terrane_format::gc::publication::{PortableSnapshot, PublicationTransaction};

    let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
    let guard = repository
        .coordinator()
        .guard()
        .held_guard(holder.destination(), clock.clone())?;
    let observed = guard.store().observe_publication().await?;
    assert_eq!(observed.state(), &acknowledged.new);
    let old = acknowledged.old.as_ref().ok_or("cold predecessor state")?;
    let predecessor = acknowledged
        .predecessor
        .as_ref()
        .ok_or("cold predecessor slot")?;
    assert_eq!(predecessor.revision, old.revision);

    // These transactions come from the independently selected native chain.
    // Equal caller-supplied transaction bytes cannot select this chain.
    let actual_candidate = observed
        .physical_reads()
        .iter()
        .filter_map(|read| {
            read.bytes()
                .and_then(|bytes| PublicationTransaction::decode(bytes).ok())
        })
        .find(|transaction| transaction.new.revision == acknowledged.new.revision)
        .ok_or("actual selected cold Candidate transaction")?;
    assert_eq!(&actual_candidate, acknowledged);
    let actual_prior = observed
        .physical_reads()
        .iter()
        .filter_map(|read| {
            read.bytes()
                .and_then(|bytes| PublicationTransaction::decode(bytes).ok())
        })
        .find(|transaction| transaction.new.revision == old.revision)
        .ok_or("actual selected preceding transaction")?;
    assert_eq!(&actual_prior.new, old);
    // The backend observation independently binds each slot digest and complete
    // predecessor to these actual transaction reads before this projection.

    let mut selected = actual_prior.snapshot.clone();
    let mut successor: Option<PortableSnapshot> = None;
    let mut logical = std::collections::BTreeMap::new();
    let mut reads = Vec::new();
    let mut visited = std::collections::BTreeSet::new();
    loop {
        assert!(
            visited.insert(selected.key.clone()),
            "snapshot predecessor cycle"
        );
        let path = repository.coordinator().store().root().join(&selected.key);
        let before = repository
            .coordinator()
            .fs()
            .symlink_metadata(&path)
            .await?;
        let bytes = repository.coordinator().fs().read_nofollow(&path).await?;
        assert_eq!(*blake3::hash(&bytes).as_bytes(), selected.digest);
        let snapshot = PortableSnapshot::decode(&bytes)?;
        assert_eq!(snapshot.encode()?, bytes);
        if let Some(current) = successor.take() {
            current.check_predecessor(&selected, &bytes)?;
        } else {
            assert_eq!(snapshot.revision, old.revision);
            assert_eq!(snapshot.origin, old.binding);
            actual_prior.check_snapshot(&bytes)?;
        }
        // Each edge independently checks exact digest, same origin and one
        // revision step. A retained None wins over older present values.
        let previous = snapshot.predecessor.clone();
        successor = Some(snapshot.clone());
        for row in snapshot.projection {
            logical.entry(row.key).or_insert(row.value);
        }
        reads.push((path, bytes, before));
        match previous {
            Some(previous) => selected = previous,
            None => break,
        }
    }
    observed.revalidate().await?;
    for (path, bytes, before) in reads {
        assert_eq!(
            repository.coordinator().fs().read_nofollow(&path).await?,
            bytes
        );
        let after = repository
            .coordinator()
            .fs()
            .symlink_metadata(&path)
            .await?;
        assert_eq!(physical_stamp(&after), physical_stamp(&before));
    }
    Ok(PriorForkSelection {
        state: actual_prior.new,
        logical,
    })
}

fn physical_stamp(
    metadata: &std::fs::Metadata,
) -> (u64, u64, u32, u32, u32, u64, i64, i64, i64, i64, u64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.nlink(),
    )
}

/// Retains immutable source and Original control images solely for preservation assertions.
pub(super) struct SourceControls {
    images: Vec<(PathBuf, Vec<u8>, std::fs::Metadata)>,
}

impl SourceControls {
    /// Captures actual selected source record, logs, Guard, lineage and Original controls.
    ///
    /// # Errors
    /// Returns errors for missing selected source dependencies, unavailable actual
    /// control bytes or metadata, invalid physical observations, or failed reads.
    pub(super) async fn capture(
        repository: &NativeRepository,
        clock: &TestClock,
        authority: &Path,
        source: &RefRecord,
    ) -> TestResult<Self> {
        let holder = SingleHeld::acquire(repository.coordinator().store()).await?;
        let guard = repository
            .coordinator()
            .guard()
            .held_guard(holder.destination(), clock.clone())?;
        let observed = guard.store().observe_publication().await?;
        let mut reads = guard
            .store()
            .selected_source_history_records(&observed, SOURCE, source)
            .await?;
        reads.push(
            guard
                .store()
                .selected_guard_snapshot_record(&observed)
                .await?
                .ok_or("actual selected Guard")?,
        );
        reads.push(
            guard
                .store()
                .selected_lineage_record(&observed, SOURCE)
                .await?
                .ok_or("actual selected source lineage")?,
        );
        // Selected history receipts contain committed log files; the whole ref
        // record lives in its separately selected immutable transaction body.
        let source_key = terrane_format::bucket::BucketKey::ref_record(SOURCE)?;
        let encoded = source.encode()?;
        reads.push(
            observed
                .physical_reads()
                .iter()
                .rev()
                .find(|read| {
                    read.bytes()
                        .and_then(|bytes| {
                            terrane_format::gc::publication::PublicationTransaction::decode(bytes)
                                .ok()
                        })
                        .is_some_and(|transaction| {
                            transaction.changes.iter().any(|change| {
                                change.key == source_key.as_str()
                                    && change.new.as_deref() == Some(encoded.as_slice())
                            })
                        })
                })
                .cloned()
                .ok_or("actual whole source record selection transaction")?,
        );
        let mut images = Vec::new();
        for read in reads {
            images.push((
                read.path().to_owned(),
                read.bytes().ok_or("actual selected control body")?.to_vec(),
                read.metadata()
                    .ok_or("actual selected control incarnation")?
                    .clone(),
            ));
        }
        for path in repository.coordinator().fs().read_dir(authority).await? {
            if path.extension() != Some(std::ffi::OsStr::new("cbor")) {
                continue;
            }
            images.push((
                path.clone(),
                repository.coordinator().fs().read_nofollow(&path).await?,
                repository
                    .coordinator()
                    .fs()
                    .symlink_metadata(&path)
                    .await?,
            ));
        }
        observed.revalidate().await?;
        // All three held objects leave scope before the public fork can lock.
        Ok(Self { images })
    }

    /// Checks that every captured immutable input keeps its whole bytes and incarnation.
    ///
    /// # Errors
    /// Returns errors when actual controls cannot be read or their metadata is unavailable.
    ///
    /// # Panics
    /// Panics when any captured source or Original control changes bytes or incarnation.
    pub(super) async fn assert_unchanged(&self, repository: &NativeRepository) -> TestResult {
        for (path, bytes, metadata) in &self.images {
            assert_eq!(
                &repository.coordinator().fs().read_nofollow(path).await?,
                bytes
            );
            assert_eq!(
                physical_stamp(&repository.coordinator().fs().symlink_metadata(path).await?),
                physical_stamp(metadata)
            );
        }
        Ok(())
    }
}
