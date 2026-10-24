//! Measures real metadata validation separately from object plaintext reads.

use crate::{
    ref_advance::CommitTiming,
    repository::{
        CommitMetadata, LocalAuthorityParameters, LocalRepositoryLocation, LocalRepositoryPolicy,
        Repository,
    },
    store::{LocalFs, TokioClock, TokioLocalFs},
    surface::{SchemaEntryKind, TreeSchema, View},
};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};
use terrane_format::{
    auth::{Authority, Grant, Verbs},
    refs::{CommitSource, Locality, PrincipalKind},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("schema fixture cleanup failed: {error}");
        }
    }
}

#[tokio::test]
async fn schema_metadata_reads_never_fetch_plaintext_chunks() -> TestResult {
    let random = TokioLocalFs.random_bytes(16).await?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let parent = Scratch(std::env::temp_dir().join(format!("terrane-schema-{suffix}")));
    std::fs::create_dir(&parent.0)?;
    std::fs::set_permissions(&parent.0, std::fs::Permissions::from_mode(0o700))?;
    let owner_uid = std::fs::metadata(&parent.0)?.uid();
    let reference = "refs/heads/_/main";
    let (repository, authority) = Repository::initialize_local(
        &LocalRepositoryLocation {
            bucket: parent.0.join("bucket"),
            authority: parent.0.join("authority"),
        },
        LocalAuthorityParameters {
            owner_uid,
            authority: Authority {
                issuer: "local".into(),
                key_id: "initial".into(),
                subject: "owner".into(),
                kind: PrincipalKind::Human,
                groups: Vec::new(),
                not_after: u64::MAX,
                not_before: None,
                token_id: random.try_into().map_err(|_| "invalid entropy")?,
                grants: vec![Grant::new("refs/**".into(), Verbs::new(31)?)?],
                workload: None,
            },
        },
        LocalRepositoryPolicy {
            store_name: "local".into(),
            domain: "private:owner".into(),
            default_private_domain: "private:owner".into(),
            acl: vec![("owner".into(), 31)],
            locality: Locality::default(),
            timing: CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            policy_authority: Some(reference.into()),
            bootstrap_properties: Vec::new(),
        },
        reference,
        TokioLocalFs,
        TokioClock,
    )
    .await?;
    let source = parent.0.join("source");
    std::fs::create_dir(&source)?;
    std::fs::write(
        source.join("file"),
        b"verified bytes that schema must not fetch",
    )?;
    let mut session = repository
        .begin(reference, authority.token(), "sdk")
        .await?;
    repository
        .commit_directory(
            &mut session,
            &source,
            &authority,
            CommitMetadata {
                message: "Publish schema fixture".into(),
                process: "schema-test".into(),
                source: CommitSource::Built,
            },
        )
        .await?;
    let observation = repository
        .coordinator
        .guard()
        .store()
        .observe_metadata_for_tests()?;
    observation.reset();

    repository
        .validate_view_schema(
            &View::parse(reference)?,
            authority.token(),
            "sdk",
            &TreeSchema {
                required_entries: vec![(b"file".to_vec(), SchemaEntryKind::File)],
                required_properties: vec![("hashes".into(), vec![vec![0x80]])],
                ..TreeSchema::default()
            },
        )
        .await?;
    let schema_counts = observation.snapshot();
    assert!(schema_counts.node_gets > 0);
    assert_eq!(schema_counts.chunk_gets, 0);

    observation.reset();
    repository
        .read_file(&View::parse(reference)?, b"file", authority.token(), "sdk")
        .await?;
    assert!(
        observation.snapshot().chunk_gets > 0,
        "positive control must exercise the real chunk counter"
    );
    Ok(())
}
