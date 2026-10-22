//! Checks genuine administrative SDK reopen after final native enrollment.
//!
//! The configured protected Original performs its own startup probes and typed
//! publication. Ordinary selected-data observations below are assertions only;
//! they do not grant a serving role publication or collection authority.

use super::{
    config::{Case, SEED},
    observations::Claims,
    source_error, stage,
};
use std::{
    fs::Metadata,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, UNIX_EPOCH},
};
use terrane_format::{
    bucket::{BucketCapabilities, BucketKey},
    chunking::ChunkProfile,
    gc::publication::PortableSnapshot,
};
use terrane_linux::host_quota::{NativeProject, open_host_path};
use terrane_sdk::{
    bucket::{
        FileBucket,
        portable_reader::{PortableReadLimits, ValidatedPortableBucket, validate_existing},
    },
    repository::MetadataValidator,
    store::{Clock, TokioClock, TokioLocalFs},
};

/// Reopens both actual Originals and checks their exact single probe publication.
///
/// # Errors
/// Returns protected registration, bounded validation, native I/O or SDK errors.
///
/// # Panics
/// Panics if the real reopen changes unrelated selected data or native custody.
pub(super) async fn run() -> io::Result<()> {
    terrane_linux::host_quota::initial_enrollment::require_initial_host_root()?;
    let case = Case::existing("positive")?;
    let claims = Claims::read_saved(&case)?;
    claims.verify_members()?;

    for owner in 0..2 {
        stage("capabilities baseline before");
        let root = open_host_path(&case.root(owner), true)?;
        let metadata = root.metadata()?;
        let project = NativeProject::inspect(&root)?;
        assert_eq!(project.project_id, case.project(owner));
        let registration_path = case.control(owner).join("backend-registration.cbor");
        let registration = open_host_path(&registration_path, false)?;
        let registration_identity = identity(&registration.metadata()?);
        let registration_bytes = read_bounded(&registration_path)?;
        let before = observe(&case, owner).await?;
        let mut expected = capabilities(&before)?;
        let baseline = seconds()?;
        assert!(expected.probed_at <= baseline);

        // Force a real timestamp delta even when enrollment and reopening occur
        // in the same clock second. The supervisor retains its original bound.
        while seconds()? <= baseline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let start = seconds()?;
        stage("capabilities Original reopen before");
        let bucket = FileBucket::open(
            case.bucket(owner, SEED),
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new(ChunkProfile::cdc_1m(SEED)),
        )
        .await
        .map_err(source_error)?;
        drop(bucket);
        stage("capabilities Original reopen after");

        let end = seconds()?;
        let after = observe(&case, owner).await?;
        let actual = capabilities(&after)?;
        assert!((start..=end).contains(&actual.probed_at));
        assert!(expected.probed_at < actual.probed_at);
        expected.probed_at = actual.probed_at;
        assert_eq!(actual, expected);
        assert_eq!(before.profile(), after.profile());
        assert_eq!(before.selected_history(), after.selected_history());
        assert_eq!(
            before
                .selected_entries()
                .filter(|(key, _)| *key != "CAPABILITIES")
                .collect::<Vec<_>>(),
            after
                .selected_entries()
                .filter(|(key, _)| *key != "CAPABILITIES")
                .collect::<Vec<_>>()
        );

        let snapshot = snapshot(&after)?;
        assert_eq!(snapshot.predecessor.as_ref(), Some(before.checkpoint()));
        assert_eq!(snapshot.projection.len(), 1);
        assert_eq!(snapshot.projection[0].key, "CAPABILITIES");
        assert_eq!(
            snapshot.projection[0].value,
            Some(actual.encode().map_err(source_error)?)
        );

        let current = open_host_path(&case.root(owner), true)?;
        let current_metadata = current.metadata()?;
        assert_eq!(identity(&metadata), identity(&current_metadata));
        assert_eq!(NativeProject::inspect(&current)?, project);
        assert_eq!(
            identity(&open_host_path(&registration_path, false)?.metadata()?),
            registration_identity
        );
        assert_eq!(read_bounded(&registration_path)?, registration_bytes);
        claims.verify_members()?;
    }

    println!(
        "PASS enrolled public and private Originals perform typed capability CAS with exact predecessor, timestamp-only delta and unchanged native custody"
    );
    Ok(())
}

async fn observe(case: &Case, owner: usize) -> io::Result<ValidatedPortableBucket> {
    validate_existing(
        case.bucket(owner, SEED),
        &TokioLocalFs,
        TokioClock,
        MetadataValidator::new(ChunkProfile::cdc_1m(SEED)),
        PortableReadLimits {
            max_file_bytes: 1024 * 1024,
            max_input_bytes: 4 * 1024 * 1024,
            max_files: 2048,
            max_selected_bytes: 1024 * 1024,
        },
    )
    .await
    .map_err(source_error)
}

fn capabilities(observation: &ValidatedPortableBucket) -> io::Result<BucketCapabilities> {
    let key = BucketKey::parse("CAPABILITIES").map_err(source_error)?;
    let bytes = observation
        .selected_value(&key)
        .flatten()
        .ok_or_else(|| io::Error::other("validated projection lacks capabilities"))?;
    BucketCapabilities::decode(bytes).map_err(source_error)
}

fn snapshot(observation: &ValidatedPortableBucket) -> io::Result<PortableSnapshot> {
    let bytes = read_bounded(&observation.root().join(&observation.checkpoint().key))?;
    assert_eq!(
        blake3::hash(&bytes).as_bytes(),
        &observation.checkpoint().digest
    );
    PortableSnapshot::decode(&bytes).map_err(source_error)
}

fn identity(metadata: &Metadata) -> (u64, u64, u32, u32, u32) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
    )
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_host_path(path, false)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("native fixture input exceeds bound"));
    }
    Ok(bytes)
}

fn seconds() -> io::Result<u64> {
    TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(source_error)
}
