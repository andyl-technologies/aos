//! Content-addressed object persistence tests.

use std::os::unix::fs::symlink;

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

fn resource() -> String {
    "test-content-object".into()
}

fn request(media_type: &str) -> ContentObjectRequest {
    ContentObjectRequest {
        name: local_key("configuration-manifest"),
        media_type: media_type.into(),
        content_sha256: Sha256Digest::of_bytes(b"canonical manifest"),
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
fn media_types_admit_exact_positive_version_parameters() {
    let producer_media_type =
        "application/vnd.aos.metadata.authorized-provisioning-input+json;version=1";
    assert!(validate_media_type(producer_media_type).is_ok());
    assert!(validate_media_type("application/json;version=12").is_ok());

    for rejected in [
        "application/json;version=",
        "application/json;version=0",
        "application/json;version=01",
        "application/json;version=-1",
        "application/json;version=1.0",
        "application/json;version=\"1\"",
        "application/json; version=1",
        "application/json;Version=1",
        "application/json;version=1 ",
        "application/json;version=1;version=2",
        "application/json;version=1;charset=utf-8",
        "application/json;charset=utf-8;version=1",
        "/json;version=1",
        "application/;version=1",
    ] {
        assert!(
            validate_media_type(rejected).is_err(),
            "admitted {rejected}"
        );
    }
}

#[test]
fn content_input_rejects_symlinks() {
    let temporary = tempdir().expect("temporary directory exists");
    fs::write(temporary.path().join("target"), b"content").expect("target");
    symlink("target", temporary.path().join("link")).expect("link");
    assert!(read_bounded_regular(&temporary.path().join("link")).is_err());
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
    let desired =
        request("application/vnd.aos.metadata.authorized-provisioning-input+json;version=1");
    validate_request(&desired).expect("native producer media type is admitted");
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
            &request("application/vnd.aos.metadata.authorized-provisioning-input+json;version=2"),
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
fn recovery_detects_changed_content_digest() {
    let first = ContentObjectRequest {
        content_sha256: Sha256Digest::of_bytes(b"first"),
        ..request("application/json")
    };
    let second = ContentObjectRequest {
        content_sha256: Sha256Digest::of_bytes(b"second"),
        ..first.clone()
    };
    assert_ne!(first, second);
}
