//! Checks fail-closed administrative SDK reopen after final native enrollment.
//!
//! The configured Original refuses its changed payload custody through the real
//! native fence. Ordinary selected-data observations below are assertions only;
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
};
use terrane_format::chunking::ChunkProfile;
use terrane_linux::host_quota::{NativeProject, open_host_path};
use terrane_sdk::{
    bucket::{
        FileBucket,
        portable_reader::{PortableReadLimits, ValidatedPortableBucket, validate_existing},
    },
    repository::MetadataValidator,
    store::{StoreErrorKind, TokioClock, TokioLocalFs},
};

/// Requires both real Originals to refuse changed custody without publication.
///
/// # Errors
/// Returns the actual final native-fence refusal after both preservation controls.
/// Other registration, validation and I/O failures stop the fixture immediately.
///
/// # Panics
/// Panics if a reopen succeeds, refuses for another reason or changes selected
/// data or native custody.
pub(super) async fn run() -> io::Result<()> {
    terrane_linux::host_quota::initial_enrollment::require_initial_host_root()?;
    let case = Case::existing("positive")?;
    let claims = Claims::read_saved(&case)?;
    claims.verify_members()?;
    let mut last_refusal = None;

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
        stage("capabilities Original reopen before");
        let refusal = FileBucket::open(
            case.bucket(owner, SEED),
            TokioLocalFs,
            TokioClock,
            MetadataValidator::new(ChunkProfile::cdc_1m(SEED)),
        )
        .await
        .err()
        .ok_or_else(|| {
            io::Error::other("enrolled payload custody unexpectedly authorized Original reopening")
        })?;
        assert!(matches!(refusal.kind(), StoreErrorKind::Unavailable { .. }));
        let native = std::error::Error::source(&refusal)
            .and_then(|error| error.downcast_ref::<io::Error>())
            .ok_or_else(|| io::Error::other("Original refusal lacks native I/O provenance"))?;
        assert_eq!(native.kind(), io::ErrorKind::Other);
        assert_eq!(native.to_string(), "unsafe native physical fence");
        stage("capabilities Original native-fence refusal");

        let after = observe(&case, owner).await?;
        assert_eq!(before.checkpoint(), after.checkpoint());
        assert_eq!(before.profile(), after.profile());
        assert_eq!(before.selected_history(), after.selected_history());
        assert_eq!(
            before.selected_entries().collect::<Vec<_>>(),
            after.selected_entries().collect::<Vec<_>>()
        );
        last_refusal = Some(source_error(refusal));

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
        "PASS both enrolled Originals refuse changed payload custody through the actual native fence without changing selected bytes, registration or native custody"
    );
    Err(last_refusal.ok_or_else(|| io::Error::other("no Original refusal was observed"))?)
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
