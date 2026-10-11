//! Atomic independent artifact enrollment without implicit source-mode changes.

// Native installation assertions deliberately panic on an invalid fixture.
// crucible-lint: allow panic-shortcut -- These artifact tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn inventory(
    catalog: &InstalledNodeCatalog,
) -> Vec<(String, InstalledIoArtifactSource, ContentRef)> {
    catalog
        .artifacts
        .iter()
        .map(|(key, artifact)| {
            (
                key.clone(),
                artifact.source.clone(),
                artifact.expected.clone(),
            )
        })
        .collect()
}

#[test]
#[ignore = "requires the actual source-built CRUCIBLE_REFERENCE_DEVICE for installed catalog measurement"]
fn independent_archive_enrollment_is_atomic_and_never_replaces_a_source_mode() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let directory = tempfile::tempdir().unwrap();
    let expected_device = measure_executable(&executable).unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable,
        expected_device,
        directory.path().to_owned(),
        Duration::from_secs(5),
        2,
    )
    .unwrap();
    let path = directory.path().join("installed-source");
    std::fs::write(&path, b"installed bytes").unwrap();
    let path_identity =
        canonical::content_ref(b"installed bytes", "application/octet-stream").unwrap();
    let archive_identity =
        canonical::content_ref(b"original archived bytes", "application/octet-stream").unwrap();
    catalog
        .install_artifacts(vec![
            InstalledIoArtifact::path(path.clone(), path_identity.clone()),
            InstalledIoArtifact::archive_only(archive_identity.clone()),
        ])
        .unwrap();
    let original = inventory(&catalog);

    assert!(
        catalog
            .install_artifacts(vec![InstalledIoArtifact::archive_only(path_identity)])
            .is_err()
    );
    assert_eq!(inventory(&catalog), original);
    assert!(
        catalog
            .install_artifacts(vec![InstalledIoArtifact::path(path, archive_identity)])
            .is_err()
    );
    assert_eq!(inventory(&catalog), original);

    let new_identity = canonical::content_ref(b"new archive", "application/octet-stream").unwrap();
    let mut oversized =
        canonical::content_ref(b"oversized archive", "application/octet-stream").unwrap();
    oversized.length = (io::MAXIMUM_IO_ARTIFACT_BYTES as u64 + 1).into();
    assert!(
        catalog
            .install_artifacts(vec![
                InstalledIoArtifact::archive_only(new_identity.clone()),
                InstalledIoArtifact::archive_only(oversized),
            ])
            .is_err()
    );
    assert_eq!(inventory(&catalog), original);

    let missing_identity =
        canonical::content_ref(b"missing path bytes", "application/octet-stream").unwrap();
    assert!(
        catalog
            .install_artifacts(vec![
                InstalledIoArtifact::archive_only(new_identity.clone()),
                InstalledIoArtifact::path(directory.path().join("missing"), missing_identity),
            ])
            .is_err()
    );
    assert_eq!(inventory(&catalog), original);
    assert_eq!(catalog.custody().reserved_worlds(), 0);
}
