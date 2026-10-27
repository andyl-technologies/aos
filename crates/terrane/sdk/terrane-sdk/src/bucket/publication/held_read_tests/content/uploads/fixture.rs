//! Publishes real optional filter rows and measures independent upload boundaries.

use super::*;
use crate::bucket::held::HeldBucket;
use crate::store::{ContentUpload, MetaUpload};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

/// Names the genuine native bucket used by the held-upload fixtures.
pub(super) type Bucket = FileBucket<ReadFs, TokioClock, Validator>;
/// Names a writable adapter borrowing its actual namespace exclusion.
pub(super) type Destination<'a> = HeldBucket<'a, ReadFs, TokioClock, Validator, true>;

/// Records actual instrumented reads and effects during one quiescent interval.
#[derive(Debug)]
pub(super) struct Trace {
    /// Contains the exact attempted `LocalFs::read_nofollow` paths, including repeats.
    pub paths: Vec<PathBuf>,
    /// Counts metadata entries, metadata dispatches and exact body-read attempts.
    pub reads: (usize, usize, usize),
    /// Counts write/effect calls and retained effects, including directory syncs.
    pub effects: (usize, usize),
}

impl Trace {
    /// Captures the current per-fixture counters without resetting them.
    ///
    /// # Panics
    /// Panics if another fixture action poisoned the read-path mutex.
    pub fn capture(bucket: &Bucket) -> Self {
        Self {
            paths: bucket.inner.fs.read_paths.lock().unwrap().clone(),
            reads: bucket.inner.fs.read_counters(),
            effects: (
                bucket.inner.fs.writes.load(Ordering::SeqCst),
                bucket.inner.fs.retained_effects.load(Ordering::SeqCst),
            ),
        }
    }

    /// Counts exact body-read attempts for one independently selected artifact.
    pub fn count(&self, path: &Path) -> usize {
        self.paths
            .iter()
            .filter(|read| read.as_path() == path)
            .count()
    }
}

/// Measures genuine selected repair and layout checks before direct verification.
///
/// # Panics
/// Panics if observation or layout checks fail, counters are poisoned, or the
/// required repair directory sync is absent.
pub(super) async fn prefix(bucket: &Bucket, destination: &Destination<'_>) -> Trace {
    bucket.inner.fs.reset_read_counters();
    let observed = destination.observe_publication().await.unwrap();
    bucket.write_layout_locked().await.unwrap();
    let trace = Trace::capture(bucket);
    assert!(
        trace.effects.1 > 0,
        "repair retains its required directory sync"
    );
    drop(observed);
    trace
}

/// Pauses the first matching read after the independently measured prefix.
///
/// # Panics
/// Panics if the actual prefix did not read the artifact or the gate mutex is poisoned.
pub(super) fn arm(
    bucket: &Bucket,
    artifact: &Path,
    prefix: &Trace,
) -> (
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let preceding_reads = prefix.count(artifact);
    assert!(
        preceding_reads > 0,
        "selected repair actually reads the row"
    );
    let (entered, arrived) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    *bucket.inner.fs.before_read_gate.lock().unwrap() = Some(CountedReadGate {
        gate: ReadGate {
            target: artifact.to_path_buf(),
            entered,
            release: released,
        },
        preceding_reads,
    });
    (arrived, release)
}

/// Collects all direct index and filter keys from the actual published generation.
///
/// # Panics
/// Panics if catalogue loading or manifest decoding fails, the generation is
/// absent, or the fixture lacks its genuinely published optional filters.
pub(super) async fn artifacts(bucket: &Bucket) -> Vec<PathBuf> {
    let catalog = bucket.catalog().await.unwrap();
    let generation = catalog.capabilities.generation.unwrap();
    let parent = bucket.root().join(format!("objects/index/{generation}"));
    let manifest = GenerationManifest::decode(
        &TokioLocalFs
            .read_nofollow(&parent.join("MANIFEST"))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut paths = Vec::new();
    for shard in manifest.shards {
        paths.push(parent.join(format!("{}.idx", shard.shard)));
        assert!(shard.filter.is_some());
        paths.push(parent.join(format!("{}.flt", shard.shard)));
    }
    assert!(!paths.is_empty());
    paths
}

/// Admits Filter data and publishes a fresh filtered generation through the native backend.
///
/// Existing generation rows remain unchanged. The body is canonical opaque
/// Filter data; the fixture does not establish any filter-algorithm invariant.
///
/// # Panics
/// Panics if fixture setup, actual admission, publication or verification fails,
/// timestamps or generations are invalid, or preserved rows/content differ.
pub(super) async fn filtered() -> ContentFixture {
    let fixture = admitted().await;
    let bucket = &fixture.bucket;
    let catalog = bucket.catalog().await.unwrap();
    let original_generation = catalog.capabilities.generation.unwrap();
    let original_key = format!("objects/index/{original_generation}/MANIFEST");
    let original_bytes = TokioLocalFs
        .read_nofollow(&bucket.root().join(&original_key))
        .await
        .unwrap();
    let original_manifest = GenerationManifest::decode(&original_bytes).unwrap();
    assert!(
        original_manifest
            .shards
            .iter()
            .all(|shard| shard.filter.is_none())
    );
    assert_eq!(
        bucket.get(&fixture.identity, None).await.unwrap(),
        fixture.encoded
    );

    // Opaque Filter semantics do not waive the owning pack's canonical CBOR
    // check. Preserve the actual typed refusal for the original plain body.
    let plain_filter = b"held-upload opaque filter artifact";
    let failure = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Filter, plain_filter).unwrap(),
        ))
        .await
        .unwrap_err();
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(crate::store::InvalidReason::Upload {
            rule_id: "STORE-33",
        })
    );

    // Independently encoded canonical CBOR: a 34-byte byte string. This is
    // ordinary Filter data, without any claimed filter-algorithm invariant.
    let filter_bytes = b"\x58\x22held-upload opaque filter artifact";
    assert_eq!(usize::from(filter_bytes[1]), plain_filter.len());
    assert_eq!(&filter_bytes[2..], plain_filter);
    let filter = bucket
        .put(ContentUpload::Meta(
            MetaUpload::new(IdentityKind::Filter, filter_bytes).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        filter,
        TERRANE_V1
            .calculate(IdentityKind::Filter, filter_bytes)
            .unwrap()
    );
    assert_eq!(bucket.get(&filter, None).await.unwrap(), filter_bytes);

    let holder = SingleHeld::acquire(bucket).await.unwrap();
    let destination = holder.destination();
    let observed = destination.observe_publication().await.unwrap();
    let mut capabilities =
        crate::bucket::publication::projection::capabilities(observed.logical()).unwrap();
    let previous_generation = capabilities.generation.unwrap();
    let previous_key = format!("objects/index/{previous_generation}/MANIFEST");
    let mut manifest =
        GenerationManifest::decode(observed.logical()[&previous_key].as_ref().unwrap()).unwrap();
    let generation = previous_generation.checked_add(1).unwrap();
    let mut changes = Vec::new();
    let mut previous_rows = Vec::new();
    for shard in &mut manifest.shards {
        let previous_key = format!("objects/index/{previous_generation}/{}.idx", shard.shard);
        let bytes = observed.logical()[&previous_key].as_ref().unwrap().clone();
        previous_rows.push((previous_key, bytes.clone()));
        changes.push(LogicalChange {
            key: format!("objects/index/{generation}/{}.idx", shard.shard),
            expected: None,
            new: Some(bytes),
        });
        shard.filter = Some((
            filter.terrane_v1_digest().unwrap(),
            filter_bytes.len() as u64,
        ));
        changes.push(LogicalChange {
            key: format!("objects/index/{generation}/{}.flt", shard.shard),
            expected: None,
            new: Some(filter_bytes.to_vec()),
        });
    }
    manifest.generation = generation;
    manifest.written_at = bucket
        .inner
        .clock
        .now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    changes.push(LogicalChange {
        key: format!("objects/index/{generation}/MANIFEST"),
        expected: None,
        new: Some(manifest.encode().unwrap()),
    });
    capabilities.generation = Some(generation);
    changes.push(LogicalChange {
        key: "CAPABILITIES".into(),
        expected: observed.logical()["CAPABILITIES"].clone(),
        new: Some(capabilities.encode().unwrap()),
    });
    let receipt = destination
        .publish_backend_raw(&observed, changes)
        .await
        .unwrap();
    let selected = destination.observe_publication().await.unwrap();
    assert_eq!(selected.stamp(), receipt.stamp);
    for (key, bytes) in previous_rows {
        assert_eq!(selected.logical()[&key].as_ref().unwrap(), &bytes);
    }
    assert_eq!(
        TokioLocalFs
            .read_nofollow(&bucket.root().join(original_key))
            .await
            .unwrap(),
        original_bytes
    );
    assert_eq!(
        destination.get(&fixture.identity, None).await.unwrap(),
        fixture.encoded
    );
    drop(selected);
    drop(observed);
    drop(destination);
    drop(holder);
    fixture
}
