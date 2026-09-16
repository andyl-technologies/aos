//! Content-addressed object persistence tests.

use std::os::unix::fs::symlink;

use aos_ability_model::{EnvironmentId, ExecutionStage, InstanceId, TransactionId};
use tempfile::tempdir;

use super::*;

struct FakeArtifactCommands;

impl ArtifactStoreCommands for FakeArtifactCommands {
    fn add_fixed(
        &self,
        _executable: &Path,
        source: &Path,
        _remaining_millis: u64,
    ) -> Result<PathBuf> {
        Ok(source.to_path_buf())
    }

    fn dump(
        &self,
        _executable: &Path,
        store_path: &Path,
        _remaining_millis: u64,
    ) -> Result<Vec<u8>> {
        let bytes = fs::read(store_path)?;
        let mut nar = b"test-flat-nar\0".to_vec();
        nar.extend(bytes);
        Ok(nar)
    }

    fn references(
        &self,
        _executable: &Path,
        _store_path: &Path,
        _remaining_millis: u64,
    ) -> Result<Vec<PathBuf>> {
        Ok(Vec::new())
    }

    fn is_valid(
        &self,
        _executable: &Path,
        store_path: &Path,
        _remaining_millis: u64,
    ) -> Result<bool> {
        Ok(store_path.is_file())
    }
}

fn local_key(value: &str) -> LocalKey {
    LocalKey::new(value).expect("fixture local key is valid")
}

fn resource() -> ResourceId {
    ResourceId {
        provider: InstanceId {
            environment: EnvironmentId {
                authority: local_key("test-authority"),
                key: local_key("test-system"),
                stage: ExecutionStage::Host,
            },
            key: local_key("artifact-provider"),
        },
        key: local_key("configuration-manifest"),
    }
}

fn request(media_type: &str) -> ContentObjectRequest {
    ContentObjectRequest {
        name: local_key("configuration-manifest"),
        media_type: media_type.into(),
        prerequisites: Vec::new(),
    }
}

#[test]
fn media_types_are_closed_canonical_tokens() {
    assert!(validate_media_type("application/vnd.aos.configuration+json").is_ok());
    assert!(validate_media_type("application/json; charset=utf-8").is_err());
    assert!(validate_media_type("application//json").is_err());
    assert!(validate_media_type("Application/JSON").is_ok());
}

#[test]
fn checked_blob_rejects_symlinks_and_changed_bytes() {
    let temporary = tempdir().expect("temporary directory exists");
    let handle = local_key("manifest");
    let bytes = b"canonical manifest";
    fs::write(temporary.path().join(handle.as_str()), bytes).expect("blob fixture is written");
    let reference = TransactionBlobReference {
        kind: TRANSACTION_BLOB_REFERENCE_TYPE.into(),
        transaction: TransactionId(local_key("transaction")),
        handle: handle.clone(),
        content_sha256: Sha256Digest::of_bytes(bytes),
        size_bytes: bytes.len() as u64,
    };

    assert_eq!(
        checked_blob_at(temporary.path(), &reference).expect("regular blob is accepted"),
        temporary.path().join(handle.as_str())
    );

    fs::write(temporary.path().join("target"), bytes).expect("target fixture is written");
    fs::remove_file(temporary.path().join(handle.as_str())).expect("regular blob is removed");
    symlink("target", temporary.path().join(handle.as_str())).expect("symlink fixture is created");
    assert!(checked_blob_at(temporary.path(), &reference).is_err());

    fs::remove_file(temporary.path().join(handle.as_str())).expect("symlink is removed");
    fs::write(temporary.path().join(handle.as_str()), b"changed").expect("changed blob is written");
    assert!(checked_blob_at(temporary.path(), &reference).is_err());
}

#[test]
fn resource_root_retains_and_reobserves_exact_artifact_identity() {
    let temporary = tempdir().expect("temporary directory exists");
    let store_directory = temporary.path().join("store");
    let root_directory = temporary.path().join("gcroots");
    fs::create_dir(&store_directory).expect("store directory is created");
    fs::create_dir(&root_directory).expect("root directory is created");
    let store_path = store_directory.join(format!("{}-configuration-manifest", "0".repeat(32)));
    fs::write(&store_path, b"canonical manifest").expect("store object is written");
    let provider = ContentArtifactProvider::test(
        root_directory,
        store_directory,
        Box::new(FakeArtifactCommands),
    );
    let desired = request("application/vnd.aos.configuration+json");
    let stored = provider
        .describe_artifact(Path::new("/test/nix-store"), &store_path, 1_000)
        .expect("artifact identity is derived");
    let metadata = ObjectMetadata {
        schema: METADATA_SCHEMA.into(),
        expected: desired.clone(),
        artifact: stored.artifact.clone(),
        content_sha256: stored.content_sha256,
    };

    provider
        .publish_root(&resource(), &store_path, &metadata)
        .expect("resource root is published");
    let observed = provider.inspect(&resource(), &desired, Path::new("/test/nix-store"), 1_000);
    let Inspection::Ready(observed) = observed else {
        panic!("published resource did not observe ready");
    };
    assert_eq!(observed.artifact, stored.artifact);
    assert_eq!(
        observed.content_sha256,
        Sha256Digest::of_bytes(b"canonical manifest")
    );

    assert!(matches!(
        provider.inspect(
            &resource(),
            &request("application/json"),
            Path::new("/test/nix-store"),
            1_000,
        ),
        Inspection::Drifted
    ));

    provider
        .remove(&resource())
        .expect("resource root is removed");
    assert!(matches!(
        provider.inspect(&resource(), &desired, Path::new("/test/nix-store"), 1_000,),
        Inspection::Absent
    ));
}

#[test]
fn semantic_revision_and_recovery_track_resolved_blob_content() {
    let temporary = tempdir().expect("temporary directory exists");
    let store_directory = temporary.path().join("store");
    let root_directory = temporary.path().join("gcroots");
    fs::create_dir(&store_directory).expect("store directory is created");
    fs::create_dir(&root_directory).expect("root directory is created");
    let first_path = store_directory.join(format!("{}-authorized-input", "0".repeat(32)));
    let second_path = store_directory.join(format!("{}-authorized-input", "1".repeat(32)));
    fs::write(&first_path, b"first canonical input").expect("first store object is written");
    fs::write(&second_path, b"second canonical input").expect("second store object is written");
    let provider = ContentArtifactProvider::test(
        root_directory,
        store_directory,
        Box::new(FakeArtifactCommands),
    );
    let expected = request("application/vnd.aos.provisioning-input+json");
    let first = provider
        .describe_artifact(Path::new("/test/nix-store"), &first_path, 1_000)
        .expect("first artifact identity is derived");
    let second = provider
        .describe_artifact(Path::new("/test/nix-store"), &second_path, 1_000)
        .expect("second artifact identity is derived");

    let first_inspection = Inspection::Ready(first.clone());
    let second_inspection = Inspection::Ready(second.clone());
    let first_observation = observation(
        "aos.test.content-observation/v1",
        &expected,
        &first_inspection,
    )
    .expect("first observation is encoded");
    let second_observation = observation(
        "aos.test.content-observation/v1",
        &expected,
        &second_inspection,
    )
    .expect("second observation is encoded");
    let first_revision =
        admission_revision(&first_inspection, &first_observation).expect("first revision exists");
    let second_revision = admission_revision(&second_inspection, &second_observation)
        .expect("second revision exists");

    assert_ne!(first_revision, second_revision);

    let requested_blob = TransactionBlobReference {
        kind: TRANSACTION_BLOB_REFERENCE_TYPE.into(),
        transaction: TransactionId(local_key("transaction")),
        handle: local_key("authorized-input"),
        content_sha256: second.content_sha256,
        size_bytes: b"second canonical input".len() as u64,
    };
    assert_eq!(
        reconciliation_disposition("commit", &first_inspection, Some(&requested_blob)),
        InvocationDisposition::SafeToRetry
    );
    assert_eq!(
        reconciliation_disposition("commit", &second_inspection, Some(&requested_blob)),
        InvocationDisposition::Completed
    );
}
